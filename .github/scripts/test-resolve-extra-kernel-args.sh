#!/usr/bin/env bash
# Tests for resolve-extra-kernel-args.sh: the workflow_dispatch input is DATA,
# so every token is validated before it becomes an imager flag.
# shellcheck disable=SC2016  # '$(id)' and '$HOME' are LITERAL test inputs, not expansions
set -u
S="$(cd "$(dirname "$0")" && pwd)/resolve-extra-kernel-args.sh"
fail=0
# Run from a directory that HAS files, as the workflow does (repo root): an
# unquoted glob in the input must not turn into file names.
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; touch "$W/Pkgfile" "$W/LICENSE" "$W/README.md"
# The non-ASCII cases only prove `export LC_ALL=C` where this locale exists; elsewhere
# bash falls back to C and they pass either way, so say so instead of passing silently.
locale -a 2>/dev/null | grep -qi '^en_US\.utf-\?8$' || echo "note: en_US.UTF-8 is not installed; the locale cases below do not exercise LC_ALL=C"
run() { (cd "$W" && LC_ALL=en_US.UTF-8 EXTRA_KARGS="$1" bash "$S"); }
ok()  { local want="$1" in="$2" got; got="$(run "$in" 2>/dev/null | paste -sd' ')"; \
        [ "$got" = "$want" ] || { echo "FAIL ok-case [$in]: got [$got] want [$want]"; fail=1; }; }
bad() { local in="$1"; run "$in" >/dev/null 2>&1 && { echo "FAIL accepted [$in]"; fail=1; }; return 0; }
# A refused input must print NOTHING: the caller reads stdout, and a partial list
# would bake only the tokens before the bad one.
nopartial() { local in="$1" out; out="$(run "$in" 2>/dev/null)"; [ -z "$out" ] || { echo "FAIL printed before refusing [$in]: [$out]"; fail=1; }; }

ok ""                                        ""                      # unset/empty: no extra args
ok ""                                        "   "                   # blanks only
ok "memhp_default_state=online"              "memhp_default_state=online"
ok "memhp_default_state=online console=ttyS0,115200n8" "  memhp_default_state=online   console=ttyS0,115200n8 "
ok "a=1"                                     "a=1 a=1"               # duplicates collapse
bad '$(id)'                                  # command substitution
bad 'a=1;rm -rf /'                           # shell metacharacter
bad '--extra-kernel-arg=x'                   # would read as a flag
bad '-x'                                     # leading dash
bad 'a="b c"'                                # quotes
bad 'a=1 b=$HOME'                            # variable expansion
bad "$(printf 'a=1\nb=2')"                   # newline smuggling a second token
bad "k=$(printf 'a%.0s' $(seq 1 200))"               # 202 characters, over the 128 limit
ok "k=$(printf 'a%.0s' $(seq 1 100))"  "k=$(printf 'a%.0s' $(seq 1 100))"   # 102 characters is fine
bad "$(seq -f 'k%g=1' 1 40 | paste -sd' ')"         # too many tokens
bad '*'                                     # glob: would expand to the file names above
bad 'P?gfile'                                # glob
bad '[A-Z]*'                                 # glob
bad 'é=1'                                    # non-ASCII must not pass [A-Za-z0-9] in a UTF-8 locale
bad 'a=é'
nopartial 'memhp_default_state=online bad;token'
nopartial 'memhp_default_state=online -x'
unset EXTRA_KARGS; got="$(bash "$S" 2>/dev/null | paste -sd' ')"; [ -z "$got" ] || { echo "FAIL unset env printed [$got]"; fail=1; }
[ "$fail" = 0 ] && echo "resolve-extra-kernel-args: ok"
exit "$fail"
