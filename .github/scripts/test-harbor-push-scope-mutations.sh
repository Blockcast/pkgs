#!/usr/bin/env bash
# Mutation sweep for the guards in harbor-push-scope-preflight.sh (BLO-39281).
#
# A guard whose test still passes when the guard is deleted is a comment. This
# removes each guard ON ITS OWN and asserts the suite goes red. One mutation at
# a time, restored in between: reverting two together lets either mask the
# other, which is exactly how an untested guard survives a sweep that looks
# thorough.
#
# A sibling of test-promote-installer-mutations.sh rather than a merge into it:
# that harness's value is its mutation CASES, which are specific to the script
# they cut into, so sharing the ~20 lines of scaffolding would buy nothing and
# would couple two gates that should be able to go red independently.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/harbor-push-scope-preflight.sh"
suite="$here/test-harbor-push-scope-preflight.sh"

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

# 1. The repository match -- take any repository entry rather than ours, so a
#    grant on some unrelated repository reads as a grant on the installer.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '    if entry.get("type") == "repository" and entry.get("name") == repo:'
assert old in s, "repository match not found -- update this mutation"
open(path, "w").write(s.replace(old, '    if entry.get("type") == "repository":', 1))
PY
assert_caught "repository match dropped (any entry counts as ours)"

# 2. The push assertion -- accept whatever Harbor granted. This is the whole
#    probe: Harbor downgrades scope and still answers 200, so without this a
#    pull-only token reports the credential as able to push.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '''  if [[ ",$actions," == *,push,* ]]; then
    echo ok
    return 0
  fi

  echo no-push'''
assert old in s, "push assertion not found -- update this mutation"
open(path, "w").write(s.replace(old, "  echo ok", 1))
PY
assert_caught "push assertion removed (any granted scope reads as push)"

# 3. The empty-actions arm -- fall through instead of failing closed, so an
#    unparseable claim or a repository Harbor never mentioned reports as a
#    verdict rather than as "not established".
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '''  if [[ -z "$actions" ]]; then
    echo no-grant
    return 0
  fi

'''
assert old in s, "empty-actions arm not found -- update this mutation"
open(path, "w").write(s.replace(old, "", 1))
PY
assert_caught "empty-actions fail-closed arm removed"

# 4. The repository validation -- accept anything, so a dispatch input can
#    rewrite the token-request query string and the probe reports a verdict
#    about a scope nobody asked for.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '  [[ "$repository" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+$ ]]'
assert old in s, "repository validation not found -- update this mutation"
open(path, "w").write(s.replace(old, "  return 0", 1))
PY
assert_caught "repository validation removed"

echo "all mutations caught"
