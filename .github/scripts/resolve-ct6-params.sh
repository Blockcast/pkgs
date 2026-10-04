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
  # linux_version is hygiene-checked incidentally -- a malformed value stops
  # matching the config-amd64 header below. talos_version is only ever compared
  # against a tag derived from itself, so a self-consistent malformation
  # survives both guards and lands a tag with spaces in $GITHUB_OUTPUT, failing
  # at docker push after the whole kernel build.
  case "$talos" in
    # %q so a trailing space or a CR from a CRLF-edited Pkgfile is visible --
    # both render as an apparently-correct value otherwise.
    *[[:space:]]*) printf '%s: talos_version contains whitespace: %q\n' "$pkgfile" "$talos" >&2; return 1 ;;
  esac

  # -F: kver's dots are BRE wildcards otherwise, so a header reading
  # "Linux/x86 6918934" would satisfy a Pkgfile declaring 6.18.34.
  # %q for the same reason as talos_version above: on a Pkgfile where only
  # linux_version carries a CR, a raw %s renders "says linux_version=6.18.34,
  # <config> header disagrees" -- an apparent self-contradiction, since the
  # value shown is the value the header contains.
  grep -qF "Linux/x86 ${kver} Kernel Configuration" "$config" ||
    { printf 'kernel mismatch: %s says linux_version=%q, %s header disagrees\n' \
        "$pkgfile" "$kver" "$config" >&2; return 1; }

  tag="${in_tag:-${talos}-amt-ct6-mroute}"
  case "$tag" in v[0-9]*.[0-9]*.[0-9]*-*) : ;; *) echo "bad image_tag: $tag" >&2; return 1 ;; esac
  # Same hazard as talos_version above, on the input a human actually types:
  # the glob's * matches spaces and newlines, and the cross-check below only
  # looks at ${tag%%-*}, so everything after the first - is unconstrained. A
  # newline here appends a second line to $GITHUB_OUTPUT.
  case "$tag" in
    *[[:space:]]*) printf 'bad image_tag, contains whitespace: %q\n' "$tag" >&2; return 1 ;;
  esac

  # Prefix test rather than [ "${tag%%-*}" = "$talos" ]: talos_version may
  # itself contain a hyphen (v1.14.0-alpha.0), and truncating at the first one
  # made this reject the tag it had just derived from $talos at :51 -- the
  # derive-then-cross-check path was not a fixpoint. "$talos" is quoted, so its
  # own characters stay literal in the pattern and only the trailing -* globs.
  case "$tag" in
    "$talos"-*) : ;;
    *) echo "image_tag '${tag}' does not name this ref's talos_version=${talos} (kernel ${kver})" >&2; return 1 ;;
  esac

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
      # printf, not echo: echo's handling of backslash escapes is shell-dependent
      # (zsh and xpg_echo bash swallow the \r in a probe key, bash alone does not),
      # so the diagnostic is only reliable through printf.
      printf "FAIL %s (rejected, but not for '%s': %s)\n" "$1" "$3" "$err"; fails=$((fails + 1))
    else
      echo "ok   $1"
    fi
  }

  ok  "empty image_tag derives from talos_version"
  [ "$(resolve "$d/Pkgfile" "$d/config" | sed -n 's/^image_tag=//p')" = "v1.13.4-amt-ct6-mroute" ] || # version-literal-ok
    { echo "FAIL derived tag is not v1.13.4-amt-ct6-mroute"; fails=$((fails + 1)); }
  ok  "matching image_tag accepted"                  v1.13.4-amt-ct6-mroute
  # The regression this guard exists for: passes the old format-only check.
  bad "production's tag from a v1.13.4 ref rejected" v1.14.0-amt-ct6-mroute
  bad "malformed image_tag rejected"                 not-a-version
  bad "bare version with no suffix rejected"         v1.13.4
  # Both pass the format glob (* matches whitespace) and the cross-check
  # (${tag%%-*} is v1.13.4), so only the dedicated guard rejects them.
  bad "space in image_tag rejected"     'v1.13.4-amt ct6'              "contains whitespace"
  bad "newline in image_tag rejected"   "$(printf 'v1.13.4-amt\nFOO=x')" "contains whitespace"

  printf '#\n# Linux/x86 6918934 Kernel Configuration\n#\n' > "$d/config"
  bad "config header matched literally, not as a regex" "" "header disagrees"
  printf '#\n# Linux/x86 6.18.34 Kernel Configuration\n#\n' > "$d/config"

  printf '#\n# Linux/x86 6.18.48 Kernel Configuration\n#\n' > "$d/config"
  bad "Pkgfile/config kernel disagreement rejected" "" "header disagrees"
  printf '#\n# Linux/x86 6.18.34 Kernel Configuration\n#\n' > "$d/config"

  # Only linux_version carries the CR, so talos_version's guard above does not
  # fire first. Keyed on the literal backslash-r that %q emits (in either
  # rendering) -- reverting to %s prints a raw CR and the message then reads as
  # a self-contradiction: the value shown is the value the header contains.
  printf 'vars:\n  linux_version: 6.18.34\r\n  talos_version: v1.13.4\n' > "$d/Pkgfile"
  bad "CR-only-on-linux_version rendered visibly" "" '\r'
  printf 'vars:\n  linux_version: 6.18.34\n  talos_version: v1.13.4\n' > "$d/Pkgfile"

  printf 'vars:\n  linux_version: 6.18.34\n  talos_version: v1.13.4   \n' > "$d/Pkgfile"
  # Keyed on the full "talos_version contains whitespace" phrase, not the bare
  # "contains whitespace": the derived tag inherits the bad value, so the
  # image_tag guard below rejects this same input and its message would
  # otherwise satisfy the probe with this guard deleted.
  bad "whitespace in talos_version rejected" "" "talos_version contains whitespace"
  printf 'vars:\n  linux_version: 6.18.34\n' > "$d/Pkgfile"
  bad "undeclared talos_version rejected" v1.13.4-amt-ct6-mroute "talos_version is not declared"
  printf 'vars:\n  talos_version: v1.13.4\n' > "$d/Pkgfile"
  bad "undeclared linux_version rejected" v1.13.4-amt-ct6-mroute "linux_version is not declared"

  # A hyphenated talos_version: Talos ships v1.14.0-alpha.N / -beta.N, and
  # truncating the derived tag at its first hyphen made the cross-check reject
  # the tag this script had just derived itself. There is no such row in
  # Pkgfile history on any branch, so this is the probe that keeps the
  # non-fixpoint from coming back rather than evidence of a live case.
  printf 'vars:\n  linux_version: 6.18.34\n  talos_version: v1.14.0-alpha.0\n' > "$d/Pkgfile"
  ok  "pre-release talos_version derives and passes its own cross-check"
  [ "$(resolve "$d/Pkgfile" "$d/config" | sed -n 's/^image_tag=//p')" = "v1.14.0-alpha.0-amt-ct6-mroute" ] || # version-literal-ok
    { echo "FAIL derived tag drops the pre-release suffix"; fails=$((fails + 1)); }
  ok  "matching pre-release image_tag accepted"      v1.14.0-alpha.0-amt-ct6-mroute
  # The prefix test must still discriminate, or replacing the cross-check with
  # `:` would pass the suite: both of these are prefix-mismatches of the alpha
  # declaration. (A pre-release *tag* on a GA ref stays accepted -- "v1.14.0"-*
  # matches v1.14.0-alpha.0-amt-... -- exactly as the old ${tag%%-*} equality
  # accepted it. Unchanged behaviour, so not asserted here.)
  bad "GA tag from a pre-release ref rejected"       v1.14.0-amt-ct6-mroute
  bad "other-minor tag from a pre-release ref rejected" v1.13.4-amt-ct6-mroute
  printf 'vars:\n  linux_version: 6.18.34\n  talos_version: v1.13.4\n' > "$d/Pkgfile"

  [ "$fails" -eq 0 ] || { echo "$fails check(s) failed" >&2; return 1; }
  echo "all checks passed"
}

usage() { echo "usage: $0 <Pkgfile> <config-amd64> [image_tag] | --self-test" >&2; exit 2; }

case "${1-}" in
  --self-test) self_test ;;
  '') usage ;;
  *) [ $# -ge 2 ] || usage; resolve "$@" ;;
esac
