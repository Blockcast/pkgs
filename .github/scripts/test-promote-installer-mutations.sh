#!/usr/bin/env bash
# Mutation sweep for the guards in promote-installer-to-harbor.sh (BLO-39281).
#
# A guard whose test still passes when the guard is deleted is a comment. This
# removes each guard ON ITS OWN and asserts the suite goes red. One mutation at
# a time, restored in between: reverting two together lets either mask the
# other, which is exactly how an untested guard survives a sweep that looks
# thorough.
#
# Lives in a script rather than inline in the workflow so it can be run locally
# before pushing, and so the Python below is not fighting YAML block-scalar
# indentation rules.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/promote-installer-to-harbor.sh"
suite="$here/test-promote-installer-to-harbor.sh"

work=$(mktemp -d)
cp "$script" "$work/pristine.sh"
restore() { cp "$work/pristine.sh" "$script"; }
trap 'restore; rm -rf "$work"' EXIT

# The suite must pass before any of this means anything: a suite that is
# already red reports every mutation as "caught" without testing anything.
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
    echo "The suite passes without this guard, so the guard is untested and" >&2
    echo "nothing would notice if it were removed. Add an assertion for it." >&2
    exit 1
  fi
  echo "mutation caught: $name"
  restore
}

# 1. The overwrite guard -- make it always permit the copy.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '''  if [[ "$overwrite" == true ]]; then
    echo copy
    return 0
  fi

  echo refuse'''
assert old in s, "overwrite guard not found -- update this mutation"
open(path, "w").write(s.replace(old, "  echo copy", 1))
PY
assert_caught "overwrite guard removed"

# 2. The absent-vs-unreadable split -- collapse it to a bare fallback, so a
#    credential failure reads as "the tag does not exist" and the script
#    overwrites whatever is actually in Harbor.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
start = s.index('EXISTING_DIGEST=$(crane digest "$DESTINATION:$TAG" 2>/dev/null) || {')
end = s.index("DECISION=$(promotion_decision")
collapsed = 'EXISTING_DIGEST=$(crane digest "$DESTINATION:$TAG" 2>/dev/null) || EXISTING_DIGEST=\n\n'
open(path, "w").write(s[:start] + collapsed + s[end:])
PY
assert_caught "absent-vs-unreadable destination split collapsed"

# 3. The post-copy digest equality assertion -- accept whatever the destination
#    resolves to. This is the check the install.image pin ultimately rests on.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'if [[ "$DEST_DIGEST" != "$SOURCE_DIGEST" ]]; then'
assert old in s, "digest equality assertion not found -- update this mutation"
open(path, "w").write(s.replace(old, 'if false; then', 1))
PY
assert_caught "post-copy digest equality assertion removed"

echo "all mutations caught"
