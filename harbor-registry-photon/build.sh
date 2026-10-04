#!/usr/bin/env bash
# Build (and optionally publish) the patched Harbor registry-photon image.
#
#   ./build.sh --print-tag   print the image reference release.env defines
#   ./build.sh --check       build + verify, publish nothing
#   ./build.sh --push        build + verify + push; refuses to repoint an
#                            existing tag; prints the pushed digest
#
# Every input comes from release.env next to this script; nothing is defaulted.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode="${1:-}"
case "$mode" in
  --print-tag|--check|--push) ;;
  *) echo "usage: $0 --print-tag|--check|--push" >&2; exit 2 ;;
esac

set -a
# shellcheck source=/dev/null
. "$here/release.env"
set +a

die() { echo "build.sh: $*" >&2; exit 1; }
require() {
  local name="$1" pattern="$2" value
  value="${!name:-}"
  [[ -n "$value" ]] || die "$name is empty in release.env"
  [[ "$value" =~ $pattern ]] || die "$name='$value' does not match $pattern"
}

digest_re='@sha256:[0-9a-f]{64}$'
require IMAGE_REPO             '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$'
require HARBOR_VERSION         '^v[0-9]+\.[0-9]+\.[0-9]+$'
require BASE_IMAGE             "$digest_re"
require PLATFORM               '^linux/[a-z0-9]+$'
require DISTRIBUTION_REPO      '^https://'
require DISTRIBUTION_SHA       '^[0-9a-f]{40}$'
require DISTRIBUTION_DESCRIBE  '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+-g[0-9a-f]+)?$'
require GOLANG_IMAGE           "$digest_re"
require PATCH_ID               '^[a-z0-9]+$'
require PATCH_REVISION         '^[1-9][0-9]*$'

[[ "$DISTRIBUTION_DESCRIBE" == *"-g${DISTRIBUTION_SHA:0:8}" ]] \
  || die "DISTRIBUTION_DESCRIBE $DISTRIBUTION_DESCRIBE does not name DISTRIBUTION_SHA $DISTRIBUTION_SHA"
compgen -G "$here/patches/*.patch" >/dev/null || die "no patches in $here/patches"

tag="${HARBOR_VERSION}-${PATCH_ID}.${PATCH_REVISION}"
ref="${IMAGE_REPO}:${tag}"

if [[ "$mode" == --print-tag ]]; then
  echo "$ref"
  exit 0
fi

build_args=(
  --platform "$PLATFORM"
  --build-arg "GOLANG_IMAGE=$GOLANG_IMAGE"
  --build-arg "BASE_IMAGE=$BASE_IMAGE"
  --build-arg "DISTRIBUTION_REPO=$DISTRIBUTION_REPO"
  --build-arg "DISTRIBUTION_SHA=$DISTRIBUTION_SHA"
  --build-arg "DISTRIBUTION_DESCRIBE=$DISTRIBUTION_DESCRIBE"
  --build-arg "PATCH_ID=$PATCH_ID"
  --build-arg "PATCH_REVISION=$PATCH_REVISION"
  --label "org.opencontainers.image.version=$tag"
  --label "org.opencontainers.image.base.name=$BASE_IMAGE"
  --label "net.blockcast.distribution.revision=$DISTRIBUTION_SHA"
  --label "net.blockcast.distribution.patch=$PATCH_ID.$PATCH_REVISION"
)
if [[ -n "${GIT_COMMIT:-}" ]]; then
  build_args+=(--label "org.opencontainers.image.revision=$GIT_COMMIT")
fi

if [[ "$mode" == --check ]]; then
  docker buildx build "${build_args[@]}" "$here"
  echo "checked (not pushed): $ref"
  exit 0
fi

# --push: never repoint a published tag. Anything other than a clean
# "not found" (auth, network, rate limit) is a failure, not a green light.
if out="$(docker buildx imagetools inspect "$ref" 2>&1)"; then
  die "$ref already exists; bump PATCH_REVISION in release.env instead of overwriting it"
fi
grep -qiE 'not found|manifest unknown' <<<"$out" \
  || die "could not determine whether $ref exists: $out"

metadata="$(mktemp)"
trap 'rm -f "$metadata"' EXIT
docker buildx build "${build_args[@]}" --metadata-file "$metadata" --push --tag "$ref" "$here"

digest="$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "implausible pushed digest: '$digest'"
grep -q "\"containerimage.digest\": *\"$digest\"" "$metadata" \
  || die "registry digest $digest does not match the build's containerimage.digest ($(cat "$metadata"))"
echo "pushed: $ref"
echo "digest: $digest"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  { echo "ref=$ref"; echo "digest=$digest"; } >> "$GITHUB_OUTPUT"
fi
