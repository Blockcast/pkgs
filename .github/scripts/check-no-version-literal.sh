#!/bin/sh
# Rejects Talos/kernel version literals in workflow input defaults, shell
# fallbacks and env blocks. Versions belong in Pkgfile (talos_version /
# linux_version), which is what the build actually reads; a literal in a
# workflow can disagree with the ref it runs on, and this repo shipped stale
# defaults for two Talos minors after the fleet moved on (BLO-39684).
#
# Usage: check-no-version-literal.sh <dir>
#        check-no-version-literal.sh --self-test
set -eu

# Every form a version literal can come back in:
#   default:      a workflow_dispatch input default
#   :[-=?]        ${X:-v}, ${X:=v}, ${X:?v}
#   [A-Z_]+[:=]   a bare `TAG=v`, an `env:` key, and `${X-v}` via its
#                 assignment prefix
# Lowercase `description:` prose is deliberately not matched -- those are
# examples, not values.
PATTERN='(default:|:[-=?]|[A-Z_]+[:=])[^#]*v?[0-9]+\.[0-9]+\.[0-9]+'

# Tool pins are not fleet versions and are correctly hardcoded. Keep this list
# short and explicit: adding to it should be a deliberate "is this a Talos or
# kernel version?" decision, not a reflex to turn the build green.
ALLOW='CRANE_VER'

# Scans a directory -- not a *.yml glob. 4 of this repo's 10 workflow files are
# .yaml, including the kres-generated ci.yaml, where a regenerated input default
# would land. Callers should hand it `.github`, not `.github/workflows`: the
# version-bearing logic now lives in `.github/scripts/` too.
#
# This file is excluded because its own probes below are literals by design.
# That is the only exclusion; a real literal anywhere else under .github is a
# hit.
scan() {
  # A prose comment *about* a removed literal is not a literal. `[^#]*` in
  # PATTERN only blocks a `#` after the marker, so full-line comments are
  # dropped here.
  grep -rnE "$PATTERN" "$1" --exclude="$(basename "$0")" 2>/dev/null |
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' |
    grep -vE "($ALLOW)[[:space:]]*[:=]"
}

self_test() {
  d="$(mktemp -d)"
  trap 'rm -rf "$d"' EXIT
  fails=0

  # $1 name, $2 catch|pass, $3 the line, $4 filename (default a.yml)
  probe() {
    rm -f "$d"/*
    printf '%s\n' "$3" > "$d/${4:-a.yml}"
    if scan "$d" >/dev/null 2>&1; then got=catch; else got=pass; fi
    if [ "$got" = "$2" ]; then
      echo "ok   $1"
    else
      echo "FAIL $1 (expected $2, got $got)"
      fails=$((fails + 1))
    fi
  }

  # The six reintroduction forms. Before BLO-39684's review only the first two
  # were caught; the other four are the regressions this suite exists for.
  probe "input default"           catch "    default: 'v1.13.4'"
  probe "shell fallback \${X:-}"   catch '          TAG="${IN_TAG:-v1.13.4-amt}"'
  probe "shell default \${X:=}"    catch '          : "${IN_TAG:=v1.13.4-amt}"'
  probe "shell fallback \${X-}"    catch '          TAG="${IN_TAG-v1.13.4-amt}"'
  probe "bare assignment"         catch '          TAG=v1.13.4-amt'
  probe "env: block"              catch '      TALOS: v1.13.4'

  # Scanning the directory rather than *.yml: this fails if the glob comes back.
  probe "literal in a .yaml file" catch "    default: 'v1.13.4'" b.yaml

  # Non-workflow files under the scan root are in scope -- the resolver lives in
  # .github/scripts/ and carries the `:-` idiom, so it is exactly the surface a
  # literal would come back on.
  probe "literal in a shell script" catch '          talos="${talos:-v1.13.4}"' c.sh

  # ...except this file, whose probes are literals by design. Fails if the
  # --exclude is dropped, which would red every run on the guard's own fixtures.
  probe "guard's own fixtures skipped" pass \
    "    default: 'v1.13.4'" check-no-version-literal.sh

  # False positives that would red the build on correct code.
  probe "tool pin left alone"     pass  '          CRANE_VER="v0.20.2"'
  probe "prose comment about a removed default" pass \
    '          # the old default: v1.13.4 was removed in BLO-39684'
  probe "description prose"       pass  "        description: 'image tag; defaults to the Pkgfile value'"
  probe "clean workflow"          pass  '    runs-on: ubuntu-latest'

  # A guard that cannot find anything to guard must not report that it found
  # nothing wrong. probe() cannot reach this -- it always creates its directory
  # -- so assert it end-to-end. Fails if the dispatch arm's -d check is dropped.
  rc=0; "$0" "$d/nope" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 2 ]; then
    echo "ok   missing scan root is an error"
  else
    echo "FAIL missing scan root is an error (expected rc 2, got $rc)"
    fails=$((fails + 1))
  fi

  [ "$fails" -eq 0 ] || { echo "$fails check(s) failed" >&2; return 1; }
  echo "all checks passed"
}

case "${1-}" in
  --self-test)
    self_test
    ;;
  '')
    echo "usage: $0 <dir> | --self-test" >&2
    exit 2
    ;;
  *)
    # `2>/dev/null` in scan() swallows permission noise on a real tree, which
    # also swallows "no such directory" -- a typo'd root would otherwise report
    # a clean bill of health. Checked here rather than in scan() so it does not
    # depend on `set -e` plus exit-through-`$()` to reach the caller.
    [ -d "$1" ] || { echo "scan root '$1' not found" >&2; exit 2; }
    hits="$(scan "$1" || true)"
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits"
      echo "^^ version literal above; declare it in Pkgfile and derive it (BLO-39684)" >&2
      exit 1
    fi
    echo "no version literals in workflow defaults, fallbacks or env blocks"
    ;;
esac
