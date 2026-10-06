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

# 5. The host validation -- accept any host, so a dispatch input can redirect
#    the preemptive-Basic-auth request and hand the Harbor credential to a
#    host of the dispatcher's choosing.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '  [[ "$host" =~ ^(harbor|registry)\\.blockcast\\.net$ ]]'
assert old in s, "host validation not found -- update this mutation"
open(path, "w").write(s.replace(old, "  return 0", 1))
PY
assert_caught "host validation removed (credential may be sent anywhere)"

# 6. The curl failure classification -- call every failure a credential
#    rejection, which is the pre-fix behaviour: a DNS or connect failure then
#    reports as "rejected the credential" and routes a network blip to a
#    credential ask.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '''  case "$1" in
    5|6|7|28|35|56|60|77) echo network ;;
    *)                    echo credential ;;
  esac'''
assert old in s, "curl failure classification not found -- update this mutation"
open(path, "w").write(s.replace(old, "  echo credential", 1))
PY
assert_caught "curl failure classification removed (network reads as credential)"

# 7. The curlrc escaping -- pass the value through, which is the pre-fix
#    behaviour: a password containing " or \ truncates the config line and
#    surfaces as an authentication FATAL, diagnosing a quoting bug as a
#    credential problem.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '''  local value=$1
  value=${value//\\\\/\\\\\\\\}
  value=${value//\\"/\\\\\\"}
  value=${value//$'\\r'/\\\\r}
  printf '%s' "${value//$'\\n'/\\\\n}"'''
assert old in s, "curlrc escaping not found -- update this mutation"
open(path, "w").write(s.replace(old, '  printf \'%s\' "$1"', 1))
PY
assert_caught "curlrc escaping removed (a quote truncates the credential line)"

# 8. The curl_failure_kind CALL SITE -- invert the branch so a network failure
#    takes the credential arm. Distinct from mutation 6, and that distinction
#    is the whole point: 6 cuts the FUNCTION, this cuts the WIRING. Reviewed at
#    dce18e5, this exact mutation left the suite AND this sweep green, because
#    nothing executed the script. It reproduces the pre-fix behaviour that
#    mutation 6 only appears to defend against.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '  if [[ "$(curl_failure_kind "$rc")" == network ]]; then'
assert old in s, "curl_failure_kind call site not found -- update this mutation"
new = '  if [[ "$(curl_failure_kind "$rc")" == credential ]]; then'
open(path, "w").write(s.replace(old, new, 1))
PY
assert_caught "curl_failure_kind call site inverted (network takes the credential arm)"

# 9. The summary PLACEMENT -- move the block back below the `case`. Every arm
#    of that case exits, so from there the summary is unreachable on exactly
#    the two FAIL verdicts a dispatcher needs rendered. This regressed once,
#    was fixed at dce18e5, and until now had nothing watching it.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
start = s.index('if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then')
end = s.index('case "$DECISION" in\n  ok)')
block = s[start:end]
assert 'GITHUB_STEP_SUMMARY' in block, "summary block not found -- update this mutation"
open(path, "w").write(s[:start] + s[end:] + "\n" + block)
PY
assert_caught "summary moved after the case (unreachable on both FAIL arms)"

# 10-12 are NARROW reverts: each cuts one behaviour out of a function that
# mutations 6/7 already cut wholesale. That is deliberate. A coarse mutation
# proves the function is tested; it does not prove each branch inside it is,
# and "simplify this case list" is a much likelier future edit than "delete
# this function".

# 10. The TLS-trust codes -- narrow the network arm back to DNS/connect/timeout
#     so an expired Harbor certificate reports as "rejected the credential" and
#     files a CTO ask over a cert renewal.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = r'    5|6|7|28|35|56|60|77) echo network ;;'
assert old in s, "network arm not found -- update this mutation"
open(path, "w").write(s.replace(old, r'    6|7|28|35) echo network ;;', 1))
PY
assert_caught "TLS-trust codes dropped from the network arm (a lapsed cert reads as a credential fault)"

# 11. The CR/LF escaping -- leave \\ and \" escaped but let a real newline
#     through, so a password containing one closes the user directive and makes
#     the remainder a second curlrc directive of its own choosing.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
# Built by concatenation rather than one triple-quoted literal: the second
# line ends in a double quote, which cannot sit flush against a closing """.
old = (r"""  value=${value//$'\r'/\\r}""" + "\n"
       + r"""  printf '%s' "${value//$'\n'/\\n}" """.rstrip())
assert old in s, "CR/LF escaping not found -- update this mutation"
new = r"""  printf '%s' "$value" """.rstrip()
open(path, "w").write(s.replace(old, new, 1))
PY
assert_caught "CR/LF escaping removed (a newline in the password injects a curlrc directive)"

# 12. The credential-ask block in the summary -- leave the verdict but drop the
#     actionable half, which is the state the reviewer found at dce18e5: the
#     ask existed only on stderr, where the person reading the Actions summary
#     UI never sees it.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
start = s.index('    if [[ -n "$ASK_NEEDS" ]]; then')
end = s.index('    fi\n', start) + len('    fi\n')
open(path, "w").write(s[:start] + s[end:])
PY
assert_caught "credential ask dropped from the summary (actionable half is log-only again)"

# 13-15. The OUTBOUND request (Ally, BLO-39281). The verdict arms above are all
#    asserted on what Harbor sends BACK; these cut what the script ASKS, which
#    the stub previously ignored, so each one left the whole suite green.

python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'scope=repository:$REPOSITORY:push,pull"'
assert old in s, "token scope not found -- update this mutation"
open(path, "w").write(s.replace(old, 'scope=repository:$REPOSITORY:pull"', 1))
PY
assert_caught "scope narrowed to pull (a push-capable principal reads as no-push)"

python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'scope=repository:$REPOSITORY:'
assert old in s, "token scope repository not found -- update this mutation"
open(path, "w").write(s.replace(old, 'scope=repository:library/other:', 1))
PY
assert_caught "scope names another repository (the verdict answers an unasked question)"

python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = ' --config "$cfg/curlrc"'
assert old in s, "curlrc attachment not found -- update this mutation"
open(path, "w").write(s.replace(old, '', 1))
PY
assert_caught "curlrc not attached (an anonymous probe reads as no-push for everyone)"

# 16. The curlrc's CONTENT (Ally, BLO-39281). Mutation 15 removes the attachment;
#     this keeps it attached but writes no credential into it.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = '"$(curlrc_escape "$HARBOR_USERNAME")" "$(curlrc_escape "$HARBOR_PASSWORD")"'
assert old in s, "curlrc credential not found -- update this mutation"
open(path, "w").write(s.replace(old, '"" ""', 1))
PY
assert_caught "curlrc attached but blank (an anonymous probe reads as no-push for everyone)"

# 17. The fail-on-HTTP-error flag (Ally, BLO-39281). Not a false-FAIL like
#     13-16: dropping -f disables a DIAGNOSIS branch. A 4xx stops being a curl
#     error, so exit 22 never occurs, curl_failure_kind's credential arm (:136)
#     becomes unreachable, and a genuinely rejected credential is misreported as
#     "answered the token request without a token" -- fail-closed, but it sends
#     the reader after the wrong fault.
python3 - "$script" <<'PY'
import sys
path = sys.argv[1]
s = open(path).read()
old = 'curl -fsS --max-time 30'
assert old in s, "curl fail flag not found -- update this mutation"
open(path, "w").write(s.replace(old, 'curl -sS --max-time 30', 1))
PY
assert_caught "curl -f dropped (a rejected credential is misreported as a tokenless answer)"

echo "all mutations caught"
