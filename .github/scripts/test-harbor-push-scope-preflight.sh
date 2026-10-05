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

# ------------------------------------------------------------------ guard 5
# Host validation. This one decides where the credential is SENT, not merely
# what is asked for: curl presents Basic auth preemptively from the curlrc, so
# an unvalidated host exfiltrates HARBOR_USERNAME/HARBOR_PASSWORD on the first
# request rather than just misreporting a verdict.

ok_host() { if valid_host "$1"; then echo yes; else echo no; fi; }

check "the default host"              "yes" "$(ok_host 'harbor.blockcast.net')"
check "the sibling name, same Harbor" "yes" "$(ok_host 'registry.blockcast.net')"
check "an arbitrary host"             "no"  "$(ok_host 'evil.example')"
check "loopback with a port"          "no"  "$(ok_host '127.0.0.1:1')"
check "a port on an allowed name"     "no"  "$(ok_host 'harbor.blockcast.net:8443')"
check "suffix attack"                 "no"  "$(ok_host 'harbor.blockcast.net.evil.example')"
check "prefix attack"                 "no"  "$(ok_host 'notharbor.blockcast.net')"
check "userinfo smuggles a host"      "no"  "$(ok_host 'harbor.blockcast.net@evil.example')"
check "dots are literal, not any-char" "no" "$(ok_host 'harborxblockcastxnet')"
check "empty"                         "no"  "$(ok_host '')"

# ------------------------------------------------------------------ guard 6
# curl failure classification. `curl -f` exits non-zero for an HTTP 4xx AND for
# never having reached the server, and calling the second "rejected the
# credential" routes a network blip to a credential ask.

check "DNS failure is network"        "network"    "$(curl_failure_kind 6)"
check "connection refused is network" "network"    "$(curl_failure_kind 7)"
check "timeout is network"            "network"    "$(curl_failure_kind 28)"
check "TLS handshake is network"      "network"    "$(curl_failure_kind 35)"
check "HTTP 4xx is credential"        "credential" "$(curl_failure_kind 22)"
check "an unknown status is credential" "credential" "$(curl_failure_kind 99)"

# TLS trust. An expired or untrusted Harbor certificate is routine and means
# the handshake never completed, so nothing is established about the
# credential. Calling these "credential" files a CTO ask over a lapsed cert.
check "untrusted peer cert is network" "network" "$(curl_failure_kind 60)"
check "unreadable CA bundle is network" "network" "$(curl_failure_kind 77)"
check "proxy resolution is network"    "network" "$(curl_failure_kind 5)"
check "truncated response is network"  "network" "$(curl_failure_kind 56)"

# ------------------------------------------------------------------ guard 7
# curlrc quoting. A password containing " or \ truncates the config line, and
# the symptom is an authentication FATAL -- a quoting bug that reads as a
# credential problem and gets routed as one.

check "an ordinary password is untouched" 'hunter2'    "$(curlrc_escape 'hunter2')"
check "a double quote is escaped"         'a\"b'       "$(curlrc_escape 'a"b')"
check "a backslash is escaped"            'a\\b'       "$(curlrc_escape 'a\b')"
check "backslash escaped before quote"    'a\\\"b'     "$(curlrc_escape 'a\"b')"

# Named for what it actually passes: the two characters b-a-c-k-s-l-a-s-h-n,
# not a newline. It pins that the escaping is literal and does not interpret.
check "a literal backslash-n is escaped, not interpreted" 'x\"\\nuser = \"y' \
  "$(curlrc_escape 'x"\nuser = "y')"

# A REAL newline, which the case above does not cover and which is worse than
# truncation: the curlrc is parsed per line, so the tail becomes a second
# directive rather than being discarded.
check "a real newline cannot start a second directive" 'x\nuser = \"y' \
  "$(curlrc_escape "$(printf 'x\nuser = "y')")"
check "a real carriage return is escaped" 'a\rb' \
  "$(curlrc_escape "$(printf 'a\rb')")"

# ------------------------------------------------------------------ guard 8
# The CALL SITES. Everything above this line sources the script
# HARBOR_PREFLIGHT_LIB_ONLY=1 and tests the pure functions in isolation. A
# correct function wired up backwards is invisible to all of it, and that is
# not hypothetical: reviewed at dce18e5, inverting the curl_failure_kind call
# site and moving the summary block back after the `case` BOTH left the whole
# suite and the whole mutation sweep green. Two guards with nothing watching
# them. This section runs the script itself so they have something.
#
# No Harbor, no network, no credential: a `curl` stub earlier on PATH answers
# with a JWT built here, so what gets exercised is the script's own
# decode -> decide -> report path.

stub=$(mktemp -d)
trap 'rm -rf "$stub"' EXIT
cat > "$stub/curl" <<'STUB'
#!/usr/bin/env bash
# Test stub. Never makes a request: exits STUB_CURL_EXIT when set, else prints
# STUB_CURL_BODY. Records its argv to STUB_CURL_ARGV, one argument per line, so
# the OUTBOUND half of the call site -- the scope asked for, and whether the
# credential curlrc is attached at all -- can be asserted too.
[[ -n "${STUB_CURL_ARGV:-}" ]] && printf '%s\n' "$@" > "$STUB_CURL_ARGV"
[[ -n "${STUB_CURL_EXIT:-}" ]] && exit "$STUB_CURL_EXIT"
printf '%s' "${STUB_CURL_BODY:-}"
STUB
chmod +x "$stub/curl"

# A Harbor token response whose access claim grants $2 on repository $1.
# Mirrors what the token endpoint mints: header.payload.signature, payload
# base64url and unpadded, exactly as the script's decoder expects.
token_json() {
  python3 - "$1" "$2" <<'PY'
import base64, json, sys
repo, actions = sys.argv[1], [a for a in sys.argv[2].split(",") if a]
claims = {"access": [{"type": "repository", "name": repo, "actions": actions}]}
payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
print(json.dumps({"token": "header.%s.signature" % payload}))
PY
}

# Runs the script against the stub. Sets RC / OUT / SUMMARY / ARGV.
run_preflight() {
  local summary_file argv_file; summary_file=$(mktemp); argv_file=$(mktemp)
  RC=0
  OUT=$(PATH="$stub:$PATH" HARBOR_USERNAME=u HARBOR_PASSWORD=p \
        GITHUB_STEP_SUMMARY="$summary_file" STUB_CURL_ARGV="$argv_file" \
        bash "$script" 2>&1) || RC=$?
  SUMMARY=$(cat "$summary_file")
  ARGV=$(cat "$argv_file")
  rm -f "$summary_file" "$argv_file"
}

has() { case "$2" in *"$1"*) echo yes ;; *) echo no ;; esac; }

# -- the three verdict arms: exit code, message, and summary reachability.

export STUB_CURL_BODY; unset STUB_CURL_EXIT

STUB_CURL_BODY=$(token_json "$REPO" "pull,push"); run_preflight
check "ok arm exits 0"                  "0"   "$RC"
check "ok arm says PASS"                "yes" "$(has 'PASS: this credential may push' "$OUT")"
check "ok arm summarises the verdict"   "yes" "$(has 'verdict: **ok**' "$SUMMARY")"
check "ok arm files no credential ask"  "no"  "$(has 'Named credential ask' "$SUMMARY")"

# The OUTBOUND half (Ally, BLO-39281). Every check above reads what came BACK,
# and the stub answers the same whatever it is asked, so the request itself was
# unpinned: asking only for pull reports a push-capable principal as no-push and
# routes a credential ask for a grant that already exists; asking about another
# repository answers a question nobody posed; dropping the curlrc probes
# anonymously, which reports no-push for every principal.
check "asks Harbor for push, not just pull" "yes" \
  "$(has "scope=repository:$REPO:push,pull" "$ARGV")"
check "asks about OUR repository"           "yes" "$(has "repository:$REPO:" "$ARGV")"
check "sends the credential curlrc"         "yes" "$(has '--config' "$ARGV")"

STUB_CURL_BODY=$(token_json "$REPO" "pull"); run_preflight
check "no-push arm exits 1"             "1"   "$RC"
check "no-push arm says NOT push"       "yes" "$(has 'but NOT push' "$OUT")"
check "no-push arm reaches the summary" "yes" "$(has 'verdict: **no-push**' "$SUMMARY")"
check "no-push summary carries the ask" "yes" "$(has 'needs: `push on Harbor project' "$SUMMARY")"

STUB_CURL_BODY=$(token_json "other/thing" "pull,push"); run_preflight
check "no-grant arm exits 1"             "1"   "$RC"
check "no-grant arm says not mentioned"  "yes" "$(has 'does not mention' "$OUT")"
check "no-grant arm reaches the summary" "yes" "$(has 'verdict: **no-grant**' "$SUMMARY")"
check "no-grant summary asks for visibility" "yes" \
  "$(has 'needs: `visibility + push' "$SUMMARY")"

# -- the curl_failure_kind CALL SITE. The function is asserted in guard 6; what
# these pin is that the right branch is wired to the right FATAL text. A
# network blip must never print the credential ask.

STUB_CURL_BODY=""; export STUB_CURL_EXIT

STUB_CURL_EXIT=6; run_preflight
check "DNS failure exits 1"               "1"   "$RC"
check "DNS failure names a NETWORK fault" "yes" "$(has 'This is a NETWORK failure' "$OUT")"
check "DNS failure routes no credential ask" "no" \
  "$(has 'Route a named credential ask' "$OUT")"

STUB_CURL_EXIT=60; run_preflight
check "untrusted cert names a NETWORK fault" "yes" "$(has 'This is a NETWORK failure' "$OUT")"

STUB_CURL_EXIT=22; run_preflight
check "HTTP 4xx exits 1"                  "1"   "$RC"
check "HTTP 4xx names an AUTH failure"    "yes" \
  "$(has 'This is an AUTHENTICATION failure' "$OUT")"

unset STUB_CURL_EXIT

# -- argument validation, at the call site rather than the function.

RC=0; OUT=$(PATH="$stub:$PATH" HARBOR_USERNAME=u HARBOR_PASSWORD=p \
  bash "$script" --host 127.0.0.1:1 2>&1) || RC=$?
check "a rejected host exits 2"            "2"   "$RC"
check "a rejected host is never contacted" "yes" \
  "$(has 'refusing to send the Harbor credential to: 127.0.0.1:1' "$OUT")"

RC=0; OUT=$(PATH="$stub:$PATH" bash "$script" 2>&1) || RC=$?
check "a missing credential exits 2"       "2"   "$RC"
check "a missing credential refuses a verdict" "yes" \
  "$(has 'refusing to report a' "$OUT")"

printf '%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
