#!/usr/bin/env bash
# Resolve + cross-check the kernel build params for build-ct6-mroute-kernel.yml.
#
# The single declared source is Pkgfile:
#   linux_version  - the tarball the build actually downloads
#   talos_version  - the Talos release this ref's kernel is built for
#
# The workflow carries no version literal, so it cannot drift from the ref it
# runs on. Two guards that used to pass independently now constrain each other
# (BLO-39684):
#   1. Pkgfile linux_version vs config-amd64's header - the build compiled one
#      kernel and shipped another's config otherwise.
#   2. image_tag's version component vs Pkgfile talos_version - a dispatch from
#      a v1.13.4 ref could otherwise republish production's v1.14.0 tag from the
#      wrong kernel.
#
# Usage: resolve-ct6-params.sh <Pkgfile> <config-amd64> [image_tag]
#        resolve-ct6-params.sh --self-test
set -euo pipefail

pkgfile_var() { sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" "$2" | head -1; }

resolve() {
  local pkgfile=$1 config=$2 in_tag=${3-} kver talos tag

  kver="$(pkgfile_var linux_version "$pkgfile")"
  talos="$(pkgfile_var talos_version "$pkgfile")"
  [ -n "$kver" ] || { echo "$pkgfile: linux_version is not declared" >&2; return 1; }
  [ -n "$talos" ] || { echo "$pkgfile: talos_version is not declared" >&2; return 1; }

  grep -q "Linux/x86 ${kver} Kernel Configuration" "$config" ||
    { echo "kernel mismatch: $pkgfile says linux_version=${kver}, $config header disagrees" >&2; return 1; }

  tag="${in_tag:-${talos}-amt-ct6-mroute}"
  case "$tag" in v[0-9]*.[0-9]*.[0-9]*-*) : ;; *) echo "bad image_tag: $tag" >&2; return 1 ;; esac

  [ "${tag%%-*}" = "$talos" ] ||
    { echo "image_tag '${tag}' claims Talos ${tag%%-*}, but this ref declares talos_version=${talos} (kernel ${kver})" >&2; return 1; }

  printf 'image_tag=%s\nkver=%s\ntalos=%s\n' "$tag" "$kver" "$talos"
}

self_test() {
  local d fails=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'vars:\n  linux_version: 6.18.34\n  talos_version: v1.13.4\n' > "$d/Pkgfile"
  printf '#\n# Linux/x86 6.18.34 Kernel Configuration\n#\n' > "$d/config"

  ok()  { if resolve "$d/Pkgfile" "$d/config" "${2-}" >/dev/null 2>&1; then echo "ok   $1"; else echo "FAIL $1 (expected pass)"; fails=$((fails + 1)); fi; }
  # $3, when given, is a substring the rejection must name. The declaration
  # guards are reachable only through their message -- the tag-format and
  # cross-check guards reject the same input on exit status alone, so without
  # this the mutation that deletes them passes the suite.
  bad() {
    local err
    if err="$(resolve "$d/Pkgfile" "$d/config" "${2-}" 2>&1 >/dev/null)"; then
      echo "FAIL $1 (expected reject)"; fails=$((fails + 1))
    elif [ -n "${3-}" ] && [ "${err#*"$3"}" = "$err" ]; then
      echo "FAIL $1 (rejected, but not for '$3': $err)"; fails=$((fails + 1))
    else
      echo "ok   $1"
    fi
  }

  ok  "empty image_tag derives from talos_version"
  [ "$(resolve "$d/Pkgfile" "$d/config" | sed -n 's/^image_tag=//p')" = "v1.13.4-amt-ct6-mroute" ] ||
    { echo "FAIL derived tag is not v1.13.4-amt-ct6-mroute"; fails=$((fails + 1)); }
  ok  "matching image_tag accepted"                  v1.13.4-amt-ct6-mroute
  # The regression this guard exists for: passes the old format-only check.
  bad "production's tag from a v1.13.4 ref rejected" v1.14.0-amt-ct6-mroute
  bad "malformed image_tag rejected"                 not-a-version
  bad "bare version with no suffix rejected"         v1.13.4

  printf '#\n# Linux/x86 6.18.48 Kernel Configuration\n#\n' > "$d/config"
  bad "Pkgfile/config kernel disagreement rejected" "" "header disagrees"
  printf '#\n# Linux/x86 6.18.34 Kernel Configuration\n#\n' > "$d/config"

  printf 'vars:\n  linux_version: 6.18.34\n' > "$d/Pkgfile"
  bad "undeclared talos_version rejected" v1.13.4-amt-ct6-mroute "talos_version is not declared"
  printf 'vars:\n  talos_version: v1.13.4\n' > "$d/Pkgfile"
  bad "undeclared linux_version rejected" v1.13.4-amt-ct6-mroute "linux_version is not declared"

  [ "$fails" -eq 0 ] || { echo "$fails check(s) failed" >&2; return 1; }
  echo "all checks passed"
}

case "${1-}" in
  --self-test) self_test ;;
  *) resolve "$@" ;;
esac
