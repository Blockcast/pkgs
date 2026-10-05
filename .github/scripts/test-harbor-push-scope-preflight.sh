#!/usr/bin/env bash
# Tests for harbor-push-scope-preflight.sh (BLO-39281).
#
# Pure bash + python against literal JSON: no Harbor, no credential, no
# network. Every guard asserted here has a failing mutation -- see
# test-harbor-push-scope-mutations.sh, which removes each one in turn and
# requires this suite to go red.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/harbor-push-scope-preflight.sh"

pass=0
fail=0

check() {
  local name=$1 expected=$2 actual=$3
  if [[ "$expected" == "$actual" ]]; then
    pass=$((pass + 1))
  else
    printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$name" "$expected" "$actual" >&2
    fail=$((fail + 1))
  fi
}

# shellcheck source=/dev/null
HARBOR_PREFLIGHT_LIB_ONLY=1 source "$script"

REPO=library/talos-installer

# ------------------------------------------------------------------ guard 1
# The repository match. A principal may legitimately hold push on some other
# repository; reading that as a grant on ours is the fail-open this guard
# exists to stop.

check "push granted on this repository" "pull,push" \
  "$(granted_actions '[{"type":"repository","name":"library/talos-installer","actions":["pull","push"]}]' "$REPO")"

check "push on a DIFFERENT repository is not ours" "" \
  "$(granted_actions '[{"type":"repository","name":"blockcast/amt-kernel-buildcache","actions":["pull","push"]}]' "$REPO")"

check "ours is found among several entries" "pull" \
  "$(granted_actions '[{"type":"repository","name":"other/thing","actions":["pull","push"]},
                       {"type":"repository","name":"library/talos-installer","actions":["pull"]}]' "$REPO")"

check "a non-repository entry of the same name is not a repository grant" "" \
  "$(granted_actions '[{"type":"registry","name":"library/talos-installer","actions":["*"]}]' "$REPO")"

# ------------------------------------------------------------------ guard 2
# The push assertion. Harbor downgrades scope and still answers 200, so a
# pull-only token is the exact shape a "did it work?" check must reject.

check "pull+push is ok"            "ok"      "$(scope_decision "pull,push")"
check "pull-only is refused"       "no-push" "$(scope_decision "pull")"
check "push alone is ok"           "ok"      "$(scope_decision "push")"

# Substring traps: these must not read as a push grant.
check "pull-only, push nowhere"    "no-push" "$(scope_decision "pull,delete")"
check "an action CONTAINING push is not push" "no-push" "$(scope_decision "pull,pushable")"
check "a prefixed action is not push"         "no-push" "$(scope_decision "repush")"

# ------------------------------------------------------------------ guard 3
# Empty must fail closed. An unparseable claim, an absent repository, or a
# token endpoint that answered with nothing all arrive here as "", and every
# one of them means "not established" -- never "allowed".

check "no entry for this repository"  "no-grant" "$(scope_decision "")"
check "empty access array"            "no-grant" "$(scope_decision "$(granted_actions '[]' "$REPO")")"
check "malformed access JSON"         "no-grant" "$(scope_decision "$(granted_actions 'not json' "$REPO")")"
check "access claim is not a list"    "no-grant" "$(scope_decision "$(granted_actions '{"access":"nope"}' "$REPO")")"
check "entry with no actions"         "no-grant" \
  "$(scope_decision "$(granted_actions '[{"type":"repository","name":"library/talos-installer"}]' "$REPO")")"

# ------------------------------------------------------------------ guard 4
# Repository validation. The value is a workflow_dispatch input that lands in
# the token-request query string; a `&` or `#` rewrites the scope actually
# requested, so the probe would answer a different question than it reports.

ok_repo()  { if valid_repository "$1"; then echo yes; else echo no; fi; }

check "plain project/repo"            "yes" "$(ok_repo 'library/talos-installer')"
check "dots and underscores"          "yes" "$(ok_repo 'blockcast/amt-kernel_build.cache')"
check "nested path"                   "yes" "$(ok_repo 'library/sub/repo')"
check "ampersand truncates the scope" "no"  "$(ok_repo 'library/x&scope=repository:other:push')"
check "hash truncates the URL"        "no"  "$(ok_repo 'library/x#frag')"
check "no project component"          "no"  "$(ok_repo 'talos-installer')"
check "empty"                         "no"  "$(ok_repo '')"
check "leading slash"                 "no"  "$(ok_repo '/library/talos-installer')"
check "whitespace"                    "no"  "$(ok_repo 'library/talos installer')"

printf '%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
