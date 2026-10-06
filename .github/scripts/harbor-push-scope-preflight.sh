#!/usr/bin/env bash
# Answer, with ZERO registry writes, whether this repo's Harbor credential may
# PUSH to the project the signed-installer promotion targets.
#
# BLO-39281. promote-installer-to-harbor.sh shipped with exactly one thing
# unproven, and its own FATAL text says so: the credential is proven to
# AUTHENTICATE -- build-ct6-mroute-kernel.yml logs in to registry.blockcast.net
# with it -- but its push scope to the `library` project was never exercised.
#
# That gap is narrower than it reads. registry.blockcast.net and
# harbor.blockcast.net are the SAME Harbor: library/talos-installer resolves to
# the identical digest through both, and both advertise
# service="harbor-registry" from their own /service/token realm. So the
# credential is already known to work against the very instance the promotion
# pushes to. What is unknown is one verb, on one project, for this principal.
#
# Without this script that question is first asked during a rollout, by a
# 30-minute build, at the moment the runbook's manual `skopeo` escape hatch no
# longer exists (it was deleted on purpose -- it published the Harbor ADMIN
# password on a human's command line). A scope failure there blocks a
# maintenance window on a credential ask. This answers it in about a second,
# any time, writing nothing.
#
# Why no push is needed: Harbor is a Docker registry v2 token server. You ask
# for a scope; it issues a token carrying the subset of that scope the
# principal actually holds, and answers 200 either way. The granted `access`
# claim IS the authorization answer. The 200 is not.
#
# This does not promote anything and is not wired into the build. It is a
# dispatchable probe -- see .github/workflows/harbor-push-scope-preflight.yml.
set -euo pipefail

# Extract the actions Harbor granted for exactly this repository.
#
# Two ways to get this wrong, both of which read as success:
#   - taking the token endpoint's 200 as the answer (Harbor downgrades scope
#     and still answers 200 -- that is the whole reason this probe works)
#   - matching any entry in the access array rather than this repository's
#     (a principal may legitimately hold grants on other repositories; one of
#     those must never be read as a grant on ours)
#
# echoes the granted actions, comma separated, empty when this repository is
# not in the claim at all.
granted_actions() {
  local access_json=$1 repository=$2
  printf '%s' "$access_json" | python3 -c '
import json, sys
repo = sys.argv[1]
try:
    access = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(access, list):
    sys.exit(0)
for entry in access:
    if not isinstance(entry, dict):
        continue
    if entry.get("type") == "repository" and entry.get("name") == repo:
        actions = entry.get("actions") or []
        print(",".join(a for a in actions if isinstance(a, str)))
        break
' "$repository"
}

# Turn the granted actions into the verdict.
#
# Kept separate from the lookup above so "Harbor named this repository but
# withheld push" and "Harbor did not name this repository at all" stay distinct
# answers. They have different causes -- a member role too low, versus a
# project or repository the principal cannot see -- and collapsing them sends
# the credential ask to the wrong place.
#
# echoes exactly one of: ok | no-push | no-grant
scope_decision() {
  local actions=$1

  # Harbor returned a token that says nothing about this repository.
  if [[ -z "$actions" ]]; then
    echo no-grant
    return 0
  fi

  if [[ ",$actions," == *,push,* ]]; then
    echo ok
    return 0
  fi

  echo no-push
  return 0
}

# Is this a repository name safe to interpolate into the token-request URL?
#
# The repository is a workflow_dispatch input and lands inside a query string,
# so `&` or `#` would silently rewrite the scope that gets asked for -- and a
# probe that asks for the wrong scope answers a question nobody posed.
# Harbor's own names are `project/repo`, lowercase with `._-` separators.
#
# returns 0 when safe
valid_repository() {
  local repository=$1
  [[ "$repository" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+$ ]]
}

# Is this a host the credential may be SENT to?
#
# Strictly more load-bearing than valid_repository, and the asymmetry is the
# point: the credential lives in a curlrc, which is preemptive Basic auth, so
# curl presents HARBOR_USERNAME/HARBOR_PASSWORD on the FIRST request to
# whatever host is named here. A bad repository misreports a verdict; a bad
# host hands the credential to a stranger.
#
# Both names are the same Harbor instance -- see this script's header.
#
# returns 0 when safe
valid_host() {
  local host=$1
  [[ "$host" =~ ^(harbor|registry)\.blockcast\.net$ ]]
}

# Did Harbor actually rule on the credential?
#
# Reporting anything else as "rejected the credential" routes a transport
# problem to a credential ask -- the one answer this script otherwise refuses
# to guess. So the CLOSED side is the one enumerated: curl exit 67 (login
# denied), or exit 22 carrying an HTTP 401 or 403. Every other failure defaults
# to network. The reverse -- listing the network codes and defaulting to
# credential -- sent a CTO ask for every exit code nobody had thought to list
# (52 empty reply, 55 send error, ...).
#
# The status is needed as well as the exit code because `curl -f` collapses
# every HTTP >= 400 into 22: a Harbor 503 mid-restart, or a 502 from a proxy,
# is 22 too and says nothing about the credential. The caller passes curl's
# --write-out '%{http_code}' for this.
#
# TLS trust (60 untrusted peer certificate, 77 unreadable CA bundle) falls on
# the network side, and must: an expired Harbor certificate is an ordinary,
# recurring operational event, and the handshake failing means the request
# never reached Harbor, so nothing whatever is established about the
# credential. Classifying those as "credential" would send a CTO ask every time
# a cert lapsed, which is the exact mis-routing this function exists to prevent.
#
# echoes exactly one of: network | credential
curl_failure_kind() {
  local rc=$1 http=${2:-}
  if [[ "$rc" == 67 ]] || [[ "$rc" == 22 && ( "$http" == 401 || "$http" == 403 ) ]]; then
    echo credential
  else
    echo network
  fi
}

# Escape a value for a double-quoted curl config entry.
#
# curl unescapes \\ and \" inside a quoted value, so a password containing
# either would otherwise truncate the line -- and the symptom is an
# authentication FATAL, i.e. a quoting bug wearing the costume of a credential
# problem. Backslash first, or the escapes we add get escaped too.
#
# CR and LF are escaped for a strictly worse reason than truncation: the curlrc
# is parsed a line at a time, so a newline inside the password does not merely
# cut the line short, it makes the remainder a SECOND directive of the
# password-holder's choosing. curl recognises \n and \r inside a quoted value,
# so this round-trips to the original bytes.
curlrc_escape() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\r'/\\r}
  printf '%s' "${value//$'\n'/\\n}"
}

# Sourced by the test for the functions above; skip the side-effecting half.
if [[ "${HARBOR_PREFLIGHT_LIB_ONLY:-0}" == 1 ]]; then
  return 0 2>/dev/null || exit 0
fi

HOST=harbor.blockcast.net
REPOSITORY=library/talos-installer

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)       HOST=$2;       shift 2 ;;
    --repository) REPOSITORY=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

valid_repository "$REPOSITORY" || {
  echo "refusing implausible Harbor repository: $REPOSITORY" >&2
  echo "Expected project/repository, lowercase. This value is interpolated into" >&2
  echo "the token-request query string, so a stray & or # would change the scope" >&2
  echo "being asked for and the verdict would describe something else." >&2
  exit 2
}

valid_host "$HOST" || {
  echo "refusing to send the Harbor credential to: $HOST" >&2
  echo "curl is configured with preemptive Basic auth, so it would present" >&2
  echo "HARBOR_USERNAME/HARBOR_PASSWORD to this host on the very first request." >&2
  echo "Allowed: harbor.blockcast.net, registry.blockcast.net (same instance)." >&2
  exit 2
}

for name in HARBOR_USERNAME HARBOR_PASSWORD; do
  [[ -n "${!name:-}" ]] || {
    echo "$name is required to probe Harbor push scope; refusing to report a" >&2
    echo "verdict without a credential -- an unauthenticated probe would report" >&2
    echo "'no push' for every principal and read as a finding." >&2
    exit 2
  }
done

# The credential goes in a 0600 config file, not on the command line: this is a
# shared runner and argv is world-readable in /proc (same reasoning as the
# umask 077 docker config in promote-installer-to-harbor.sh).
umask 077
cfg=$(mktemp -d)
trap 'rm -rf "$cfg"' EXIT
printf 'user = "%s:%s"\n' \
  "$(curlrc_escape "$HARBOR_USERNAME")" "$(curlrc_escape "$HARBOR_PASSWORD")" > "$cfg/curlrc"

echo "probing push scope: $HOST/$REPOSITORY"

# The body goes to a file so stdout carries only the HTTP status, which is what
# lets curl_failure_kind tell a 401 from a 503 -- `-f` reports both as exit 22.
http_code=$(curl -fsS --max-time 30 --config "$cfg/curlrc" \
  --output "$cfg/response" --write-out '%{http_code}' \
  "https://$HOST/service/token?service=harbor-registry&scope=repository:$REPOSITORY:push,pull") || {
  rc=$?
  if [[ "$(curl_failure_kind "$rc" "$http_code")" == network ]]; then
    echo "FATAL: no credential verdict from the Harbor token endpoint at $HOST (curl exit $rc, HTTP $http_code)." >&2
    echo "This is a NETWORK failure -- DNS, connection, timeout, TLS, or an HTTP" >&2
    echo "error other than 401/403. Harbor never ruled on the credential, so" >&2
    echo "NOTHING is established about it or its scope. Retry. Do not route a" >&2
    echo "credential ask on this." >&2
  else
    echo "FATAL: the Harbor token endpoint at $HOST rejected the credential (curl exit $rc, HTTP $http_code)." >&2
    echo "This is an AUTHENTICATION failure, not a scope one: the request never" >&2
    echo "got far enough to be downgraded. Check HARBOR_USERNAME/HARBOR_PASSWORD" >&2
    echo "in Blockcast/pkgs. Route a named credential ask; do not widen a grant here." >&2
  fi
  exit 1
}
response=$(cat "$cfg/response")

token=$(printf '%s' "$response" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("token") or "")
except Exception:
    print("")
')
[[ -n "$token" ]] || {
  echo "FATAL: $HOST answered the token request without a token." >&2
  exit 1
}

# Decode the JWT payload (base64url, unpadded). The signature is Harbor's to
# verify -- this reads the claim Harbor just minted for us and is not a trust
# decision about a token from elsewhere.
access=$(printf '%s' "$token" | python3 -c '
import base64, json, sys
tok = sys.stdin.read().strip()
parts = tok.split(".")
if len(parts) < 2:
    print("[]"); raise SystemExit(0)
payload = parts[1]
payload += "=" * (-len(payload) % 4)
try:
    claims = json.loads(base64.urlsafe_b64decode(payload))
except Exception:
    print("[]"); raise SystemExit(0)
print(json.dumps(claims.get("access") or []))
')

ACTIONS=$(granted_actions "$access" "$REPOSITORY")
DECISION=$(scope_decision "$ACTIONS")

echo "granted actions for $REPOSITORY: ${ACTIONS:-<none>}"

# The named credential ask, written once. Both the Actions summary below and
# the FAIL arms further down quote it, and they must not drift: the summary is
# what the person who dispatched this actually reads, the stderr block is what
# gets pasted into the ask. Two hand-maintained copies of the same sentence is
# how those stop matching.
ASK_CREDENTIAL="HARBOR_USERNAME/HARBOR_PASSWORD in Blockcast/pkgs"
# The project is the repository's first component (valid_repository already
# requires project/repo), so the ask names the project actually probed. A
# hardcoded 'library' sends a dispatch for apps/widget to a project nobody asked
# about.
PROJECT=${REPOSITORY%%/*}
case "$DECISION" in
  no-push)  ASK_NEEDS="push on Harbor project '$PROJECT' (repository $REPOSITORY)" ;;
  no-grant) ASK_NEEDS="visibility + push on Harbor project '$PROJECT' (repository $REPOSITORY)" ;;
  *)        ASK_NEEDS="" ;;
esac

# Emitted BEFORE the verdict is acted on, because every arm below exits. The
# answer a human dispatching this most needs rendered in the Actions summary UI
# is the one where push is WITHHELD -- and that is precisely the arm that never
# reached a summary when this block sat at the end of the script.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### Harbor push-scope preflight\n\n'
    printf -- '- target: `%s/%s`\n' "$HOST" "$REPOSITORY"
    printf -- '- granted: `%s`\n' "${ACTIONS:-<none>}"
    printf -- '- verdict: **%s**\n' "$DECISION"
    printf -- '- nothing was written to any registry\n'
    # The verdict alone tells the dispatcher it failed, not what to do about
    # it. The ask is the actionable half and was previously log-only.
    if [[ -n "$ASK_NEEDS" ]]; then
      printf '\n**Named credential ask -- route to the CTO. Do not widen a grant here.**\n\n'
      printf -- '- credential: `%s`\n' "$ASK_CREDENTIAL"
      printf -- '- needs: `%s`\n' "$ASK_NEEDS"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

case "$DECISION" in
  ok)
    echo "PASS: this credential may push to $HOST/$REPOSITORY."
    echo "The signed-installer promotion's one unproven precondition is now proven."
    ;;
  no-push)
    echo "FAIL: this credential may [$ACTIONS] on $HOST/$REPOSITORY but NOT push." >&2
    echo "Harbor named the repository and withheld push, so the principal can see" >&2
    echo "the project and its member role is too low -- not a visibility problem." >&2
    echo "This is the named credential ask BLO-39281 anticipated:" >&2
    echo "  credential: $ASK_CREDENTIAL" >&2
    echo "  needs:      $ASK_NEEDS" >&2
    echo "Route it to the CTO. Do not widen the grant here, and do not restore the" >&2
    echo "admin-credential skopeo recipe the rollout runbook deleted." >&2
    exit 1
    ;;
  no-grant)
    echo "FAIL: Harbor issued a token that does not mention $REPOSITORY at all." >&2
    echo "Distinct from a withheld push: the principal likely cannot see the" >&2
    echo "project or the repository, so granting push alone may not be the fix." >&2
    echo "  credential: $ASK_CREDENTIAL" >&2
    echo "  needs:      $ASK_NEEDS" >&2
    echo "Route a named credential ask to the CTO rather than widening a grant here." >&2
    exit 1
    ;;
  *)
    echo "internal error: unrecognised scope decision: $DECISION" >&2
    exit 1
    ;;
esac
