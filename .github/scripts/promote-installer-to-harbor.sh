#!/usr/bin/env bash
# Mirror the signed installer this run just pushed to GHCR into the on-prem
# Harbor, by digest, in the same run that built it.
#
# BLO-39281. The fleet's `install.image` is pinned to
# harbor.blockcast.net/library/talos-installer@sha256:...; ghcr.io is not a
# registry the Talos nodes can pull from (they carry no ghcr credential --
# see the operator's 2026-09-28 note on BLO-34416: "Talos has no ghcr
# credentials"). So every signed installer has needed a hand-run `skopeo copy`
# out of the rollout runbook before it could be deployed. That step published
# the Harbor ADMIN password on a human's command line, read out of the
# `harbor-bootstrap-secrets` cluster secret, every single time. Removing that
# is the point of this script; the toil is the lesser half.
#
# This is the producer-side convention onprem-k8s already enforces on itself
# in scripts/check-ghcr-harbor-promotion.sh -- "a workflow that pushes a
# private image to GHCR must also make that exact manifest available in
# Harbor" -- which four builders there satisfy via its
# .github/actions/promote-ghcr-to-harbor. That gate cannot see this repo, which
# is the only reason the installer was ever exempt.
#
# crane, not `docker buildx imagetools`: compose-signed-installer.yml runs on
# chromium-build WITHOUT setup-buildx-action (unlike build-ct6-mroute-kernel.yml,
# which installs it explicitly), so buildx is not available here. And not
# `docker push`: re-pushing re-encodes the manifest and does not preserve the
# digest, which is the one property the pin depends on.
#
# No reviewed lock file, deliberately. The lock files in onprem-k8s's ceph and
# moq-player promotions exist because those promote an EXTERNALLY built image
# chosen at dispatch time, so the digest needs review before it is trusted.
# Here the digest is whatever this run just built and signed two steps ago;
# pinning it in git would review a value that cannot be anything else.
set -euo pipefail

# Decide what to do about the destination tag.
#
# Split out as a pure function with no registry access so it can be exercised
# directly -- see test-promote-installer-to-harbor.sh. A guard with no failing
# mutation is a comment, and this one is the difference between re-publishing a
# tag the runbook resolves digests through and refusing to. That read is
# Blockcast/onprem-k8s .planning/2026-07-17-amt-6.18.38-secureboot-rollout-runbook.md
# §1 -- re-verify there rather than re-deriving this premise (BLO-39281).
#
#   existing  destination digest, empty when the tag does not exist
#   source    digest this run pushed
#   overwrite "true" to allow repointing a tag at a different digest
#
# echoes exactly one of: copy | skip | refuse
promotion_decision() {
  local existing=$1 source=$2 overwrite=$3

  # Tag is new. Nothing can be clobbered.
  if [[ -z "$existing" ]]; then
    echo copy
    return 0
  fi

  # Already the same content. Re-promotion is a no-op, which keeps a re-run of
  # a failed job idempotent rather than making it an overwrite that needs a
  # flag.
  if [[ "$existing" == "$source" ]]; then
    echo skip
    return 0
  fi

  # Tag exists and means something else. The runbook resolves the digest it
  # pins by reading this tag.
  if [[ "$overwrite" == true ]]; then
    echo copy
    return 0
  fi

  echo refuse
  return 0
}

# Sourced by the test for the function above; skip the side-effecting half.
if [[ "${PROMOTE_INSTALLER_LIB_ONLY:-0}" == 1 ]]; then
  return 0 2>/dev/null || exit 0
fi

SOURCE=
DESTINATION=harbor.blockcast.net/library/talos-installer
OVERWRITE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)      SOURCE=$2;      shift 2 ;;
    --destination) DESTINATION=$2; shift 2 ;;
    --overwrite)   OVERWRITE=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$SOURCE" ]] || { echo "--source ghcr.io/<repo>:<tag> is required" >&2; exit 2; }

# Reject anything that is not a tagged ghcr reference. A digest-only source has
# no tag to carry across, and a non-ghcr source is not what this run built.
# `ghcr.io/*:*` alone matches a digest ref too -- `@sha256:` supplies the `:` --
# so exclude `@` explicitly.
[[ "$SOURCE" == ghcr.io/*:* && "$SOURCE" != *@* ]] || {
  echo "--source must be a tagged ghcr.io reference, got: $SOURCE" >&2
  exit 2
}
TAG=${SOURCE##*:}
[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "refusing implausible destination tag derived from source: $TAG" >&2
  exit 2
}

command -v crane >/dev/null 2>&1 || {
  echo "crane is required on this runner; install it before calling this script" >&2
  exit 1
}

# The digest this run published. Read from ghcr rather than from `docker push`
# output so the value is the registry's own, not the local daemon's.
SOURCE_DIGEST=$(crane digest "$SOURCE") || {
  echo "could not read the source digest for $SOURCE from ghcr.io" >&2
  exit 1
}
[[ "$SOURCE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "implausible source digest: $SOURCE_DIGEST" >&2
  exit 1
}
echo "source $SOURCE -> $SOURCE_DIGEST"

# Absent tag and unreadable registry are different answers, and only the first
# is safe to treat as "nothing there". `crane digest` exits non-zero for both,
# so a bare `|| existing=''` would silently convert a credential failure into a
# clobber. Distinguish them by asking whether the repository lists at all.
EXISTING_DIGEST=$(crane digest "$DESTINATION:$TAG" 2>/dev/null) || {
  if crane ls "$DESTINATION" >/dev/null 2>&1; then
    EXISTING_DIGEST=
  else
    echo "FATAL: cannot read $DESTINATION from Harbor." >&2
    echo "Listing the repository failed, which has two causes this script cannot" >&2
    echo "tell apart: a credential/scope problem, or a repository that does not" >&2
    echo "exist yet (Harbor answers 404 on tags/list for a never-pushed repository," >&2
    echo "so a first-ever promotion into a new repository also lands here). Neither" >&2
    echo "is safe to treat as an absent tag: in the first case that would overwrite" >&2
    echo "whatever is actually there. The push credential is HARBOR_USERNAME/HARBOR_PASSWORD" >&2
    echo "in Blockcast/pkgs." >&2
    echo "" >&2
    echo "Tell the two causes apart WITHOUT writing anything: dispatch" >&2
    echo "harbor-push-scope-preflight.yml in this repo. It asks Harbor for a push" >&2
    echo "token and reports the scope actually granted, which separates 'the" >&2
    echo "credential may not push here' from 'the repository does not exist yet'." >&2
    echo "If it reports a scope problem, route a named credential ask rather than" >&2
    echo "widening any grant here." >&2
    exit 1
  fi
}

DECISION=$(promotion_decision "$EXISTING_DIGEST" "$SOURCE_DIGEST" "$OVERWRITE")

case "$DECISION" in
  skip)
    echo "destination $DESTINATION:$TAG already resolves to $SOURCE_DIGEST; nothing to do"
    ;;
  refuse)
    echo "FATAL: $DESTINATION:$TAG already exists and points at a DIFFERENT image." >&2
    echo "  existing: $EXISTING_DIGEST" >&2
    echo "  source:   $SOURCE_DIGEST" >&2
    echo "Nodes already rolled are unaffected -- install.image is digest-pinned," >&2
    echo "and the runbook's rollback names digests too. What breaks is the digest" >&2
    echo "READ: the runbook resolves the digest it pins by reading this tag, so" >&2
    echo "after a repoint it hands out this build for nodes rolled on the old one." >&2
    echo "Publish under a new tag, or pass --overwrite if repointing is intended." >&2
    exit 1
    ;;
  copy)
    echo "promoting $SOURCE_DIGEST -> $DESTINATION:$TAG"
    crane copy "$SOURCE@$SOURCE_DIGEST" "$DESTINATION:$TAG"
    ;;
  *)
    echo "internal error: unrecognised promotion decision: $DECISION" >&2
    exit 1
    ;;
esac

# Digest equality after the copy. crane copy preserves the manifest bytes, so
# this asserts the property the install.image pin depends on rather than
# assuming it.
DEST_DIGEST=$(crane digest "$DESTINATION:$TAG")
if [[ "$DEST_DIGEST" != "$SOURCE_DIGEST" ]]; then
  echo "FATAL: destination digest does not match source after copy" >&2
  echo "  source:      $SOURCE_DIGEST" >&2
  echo "  destination: $DEST_DIGEST" >&2
  exit 1
fi
echo "verified $DESTINATION:$TAG = $DEST_DIGEST"

# Prove the path the cluster actually uses. The nodes hold no Harbor credential
# for this project -- `library` is public -- so an authenticated pull proving
# nothing about their path is the failure mode worth excluding. Empty
# DOCKER_CONFIG, so no login from earlier steps can leak in and make this pass.
anonymous_config=$(mktemp -d)
trap 'rm -rf "$anonymous_config"' EXIT
anon_digest=$(DOCKER_CONFIG="$anonymous_config" crane digest "$DESTINATION:$TAG")
if [[ "$anon_digest" != "$SOURCE_DIGEST" ]]; then
  echo "FATAL: anonymous (secret-free) resolve of $DESTINATION:$TAG did not match" >&2
  exit 1
fi
echo "anonymous pull path verified: $DESTINATION:$TAG = $anon_digest"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  # printf -- : a format string starting with '-' is parsed as an option by the bash builtin.
  {
    printf '### Harbor promotion\n\n'
    printf -- '- source: `%s`\n' "$SOURCE"
    printf -- '- destination: `%s:%s`\n' "$DESTINATION" "$TAG"
    printf -- '- digest: `%s` (%s)\n' "$SOURCE_DIGEST" "$DECISION"
    printf -- '- anonymous pull verified\n\n'
    printf 'Deploy with:\n\n```\ntalosctl upgrade --image %s@%s\n```\n' \
      "$DESTINATION" "$SOURCE_DIGEST"
  } >> "$GITHUB_STEP_SUMMARY"
fi
