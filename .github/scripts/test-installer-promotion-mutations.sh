#!/usr/bin/env bash
# Mutation sweep for check-installer-promotion-drift.sh (BLO-39281).
#
# Same rule as test-promote-installer-mutations.sh: a guard whose suite still
# passes when the guard is deleted is a comment. One mutation at a time,
# restored in between.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/check-installer-promotion-drift.sh"
suite="$here/test-installer-promotion-drift.sh"

work=$(mktemp -d)
cp "$script" "$work/pristine.sh"
restore() { cp "$work/pristine.sh" "$script"; }
trap 'restore; rm -rf "$work"' EXIT

if ! "$suite" >/dev/null 2>&1; then
  echo "FATAL: the suite is red before any mutation; fix that first" >&2
  "$suite" || true
  exit 1
fi
echo "baseline: suite green"

assert_caught() {
  local name=$1
  if "$suite" >/dev/null 2>&1; then
    echo "MUTATION NOT CAUGHT: $name" >&2
    echo "The suite passes without this guard, so the guard is untested." >&2
    exit 1
  fi
  echo "mutation caught: $name"
  restore
}

# 1. The invocation arm -- the whole point of the guard. Without it a ref that
#    never mirrors anything reports OK.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = "if ! sed 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//' \"$REF_WORKFLOW\" 2>/dev/null \\"
assert old in s, "invocation arm not found -- update this mutation"
open(path, "w").write(s.replace(old, "if false && grep -v . \"$REF_WORKFLOW\" 2>/dev/null \\", 1))
PY
assert_caught "invocation arm removed"

# 2. The identity arm. Without it a build branch may carry a drifted copy of the
#    promotion script, whose guards are tested only on main.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'if ! cmp -s "$REF_SCRIPT" "$CANONICAL_SCRIPT" 2>/dev/null; then'
assert old in s, "identity arm not found -- update this mutation"
open(path, "w").write(s.replace(old, "if false; then", 1))
PY
assert_caught "identity arm removed"

# 3. The failing exit itself. Both arms can report correctly and still let the
#    run go green if the script exits 0 regardless -- which is the shape this
#    guard exists to prevent in the first place.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'if [[ "$fail" -ne 0 ]]; then\n  exit 1\nfi'
assert old in s, "terminal exit not found -- update this mutation"
open(path, "w").write(s.replace(old, 'if false; then\n  exit 1\nfi', 1))
PY
assert_caught "failing exit removed"

# 4. Comment stripping. Without it a commented-out promotion step -- the
#    likeliest way a build branch disables the mirror -- reports OK.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = "sed 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//' \"$REF_WORKFLOW\" 2>/dev/null"
assert old in s, "comment stripping not found -- update this mutation"
open(path, "w").write(s.replace(old, "cat \"$REF_WORKFLOW\" 2>/dev/null", 1))
PY
assert_caught "comment stripping removed"

# 5. List-item stripping. Without it a `paths:` filter entry naming the script
#    reads as a call.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = "| grep -Ev '^[[:space:]]*-[[:space:]]+[^[:space:]]*promote-installer-to-harbor\\.sh[^[:space:]]?[[:space:]]*$' \\"
assert old in s, "list-item stripping not found -- update this mutation"
open(path, "w").write(s.replace(old, "| cat \\", 1))
PY
assert_caught "list-item stripping removed"

# 6. Inline-comment stripping alone. Without it a step whose `run:` line keeps
#    the call only after a trailing `#` reads as a call; whole-line stripping
#    (mutation 4) cannot see that case.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = "sed 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//'"
assert old in s, "inline-comment stripping not found -- update this mutation"
open(path, "w").write(s.replace(old, "sed 's/^[[:space:]]*#.*$//'", 1))
PY
assert_caught "inline-comment stripping removed"

echo "all mutations caught"
