#!/usr/bin/env bash
# Tests for promote-installer-to-harbor.sh (BLO-39281).
#
# Pure bash against a stubbed `crane`: no registry, no credential, no network.
# Every guard asserted here has a failing mutation -- see
# test-promote-installer-mutations.sh, which removes each one in turn and
# requires this suite to go red.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/promote-installer-to-harbor.sh"

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

expect_output() {
  local name=$1 needle=$2 haystack=$3
  if grep -q "$needle" <<<"$haystack"; then
    pass=$((pass + 1))
  else
    printf 'FAIL: %s\n  expected output matching: %s\n  got: %s\n' "$name" "$needle" "$haystack" >&2
    fail=$((fail + 1))
  fi
}

A=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# --------------------------------------------------------------- guard 1
# The overwrite guard, as a pure decision over (existing, source, overwrite).
PROMOTE_INSTALLER_LIB_ONLY=1 . "$script"

check "absent tag copies"               copy   "$(promotion_decision ""  "$A" false)"
check "identical digest skips"          skip   "$(promotion_decision "$A" "$A" false)"
check "differing digest refuses"        refuse "$(promotion_decision "$B" "$A" false)"
check "differing digest copies with -f" copy   "$(promotion_decision "$B" "$A" true)"
# --overwrite authorises repointing; it does not compel a redundant copy.
check "identical digest skips with -f"  skip   "$(promotion_decision "$A" "$A" true)"

# ----------------------------------------------------------- end-to-end
stub_dir=$(mktemp -d)
trap 'rm -rf "$stub_dir"' EXIT

# A `crane` stub with enough state to model the destination before AND after a
# copy. Without the "after" half the post-copy verification is never reached,
# and its guards could not be tested at all.
#
#   CRANE_LS_STATUS    0 = destination repo readable, 1 = unreadable
#   CRANE_DEST_BEFORE  destination digest before copy, empty = tag absent
#   CRANE_DEST_AFTER   what the destination resolves to after copy
#   CRANE_DEST_ANON    what a credential-free resolve of the destination returns;
#                      unset = same as an authenticated one
#
# "Credential-free" is modelled the way crane decides it: DOCKER_CONFIG names a
# directory with no config.json. run_promote hands the script an authenticated
# DOCKER_CONFIG, as the workflow does, so an anonymous-pull check that forgets
# to override it resolves with credentials and the stub can tell.
cat > "$stub_dir/crane" <<'STUB'
#!/usr/bin/env bash
state="$CRANE_STATE"
case "$1" in
  digest)
    case "$2" in
      ghcr.io/*) echo "$CRANE_SOURCE"; exit 0 ;;
      *)
        if [ -n "${CRANE_DEST_ANON:-}" ] && [ -n "${DOCKER_CONFIG:-}" ] \
           && [ ! -f "$DOCKER_CONFIG/config.json" ]; then
          echo "$CRANE_DEST_ANON"; exit 0
        elif [ -f "$state" ]; then
          echo "$CRANE_DEST_AFTER"; exit 0
        elif [ -n "$CRANE_DEST_BEFORE" ]; then
          echo "$CRANE_DEST_BEFORE"; exit 0
        fi
        exit 1 ;;
    esac ;;
  ls)   exit "$CRANE_LS_STATUS" ;;
  copy) : > "$state"; echo "stub: copied $2 -> $3"; exit 0 ;;
esac
exit 0
STUB
chmod +x "$stub_dir/crane"
mkdir "$stub_dir/auth"
echo '{}' > "$stub_dir/auth/config.json"

run_promote() {
  # usage: run_promote <ls_status> <dest_before> <dest_after> [extra args...]
  local ls=$1 before=$2 after=$3; shift 3
  CRANE_STATE="$stub_dir/copied.$$.$RANDOM" \
  CRANE_SOURCE="$A" CRANE_LS_STATUS="$ls" \
  CRANE_DEST_BEFORE="$before" CRANE_DEST_AFTER="$after" \
  DOCKER_CONFIG="$stub_dir/auth" \
  PATH="$stub_dir:$PATH" "$script" \
    --source ghcr.io/blockcast/installer:v0.0.0-test \
    --destination harbor.example.invalid/library/talos-installer "$@" 2>&1 || true
}

# guard 2 -- "tag absent" and "registry unreadable" are different answers, and
# `crane digest` fails identically for both. Conflating them turns a credential
# fault into a silent overwrite of whatever is really there.
expect_output "unreadable destination aborts"  'FATAL: cannot read' "$(run_promote 1 '' "$A")"
expect_output "readable + absent tag promotes" 'promoting'          "$(run_promote 0 '' "$A")"

# guard 1, end to end
expect_output "existing differing tag refuses" 'already exists and points at a DIFFERENT' "$(run_promote 0 "$B" "$A")"
expect_output "existing differing tag with -f" 'promoting'     "$(run_promote 0 "$B" "$A" --overwrite)"
expect_output "existing identical tag no-ops"  'nothing to do' "$(run_promote 0 "$A" "$A")"

# guard 3 -- post-copy digest equality. This is what the fleet's install.image
# pin ultimately rests on, so a copy that lands different bytes must fail
# loudly rather than report success.
expect_output "post-copy digest mismatch aborts" \
  'destination digest does not match source' "$(run_promote 0 '' "$B")"
# ...and the happy path still reaches the anonymous-pull proof.
expect_output "verified copy proves anonymous pull" \
  'anonymous pull path verified' "$(run_promote 0 '' "$A")"
# guard 4 -- the anonymous resolve must actually be credential-free. Here the
# authenticated path sees the copy and the anonymous one does not; only a check
# that really drops the job's credentials notices.
expect_output "anonymous resolve mismatch aborts" \
  'FATAL: anonymous (secret-free) resolve' "$(CRANE_DEST_ANON="$B" run_promote 0 '' "$A")"

# ------------------------------------------------------------ arg checks
# Assert the rejection message, not just a non-zero exit: with no stub state the
# run fails later anyway (empty source digest), so exit status alone cannot tell
# a rejected --source from one the guard let through.
for bad in "ghcr.io/blockcast/installer" "docker.io/blockcast/installer:v1" \
  "ghcr.io/blockcast/installer@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"; do
  expect_output "--source $bad rejected" 'must be a tagged ghcr.io reference' \
    "$(PATH="$stub_dir:$PATH" "$script" --source "$bad" 2>&1 || true)"
done

printf '%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
