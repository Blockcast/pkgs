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
#   [A-Z_]+[:=]   an `env:` key (`TALOS: v1.13.4`), and `${X-v}` via its
#                 assignment prefix
#   [A-Za-z_]+=   any bare assignment. Lowercase is the idiom .github/scripts/
#                 is written in (`local pkgfile=$1 ... kver talos tag`), so an
#                 uppercase-only arm missed `talos=v1.13.4` and `kver=6.18.34`
#                 outright -- the clean pass over this subtree was incidental,
#                 not designed (BLO-39887).
#   ^<ws>v?N.N.N  a value alone on its line: the YAML block-scalar form,
#                 `default: >-` with the value on the next line. Approximated
#                 as "the whole line is a version" rather than by tracking the
#                 opener, because grep is line-at-a-time. Measured zero false
#                 positives over .github: every `|`/`>` block here is a
#                 `run:`/`script:`/`payload:` body, and a bare version alone on
#                 a line is not a valid command in one.
#
# KNOWN FALSE POSITIVE: a dotted quad. `group=239.1.1.1`, `src=10.0.0.1`,
# `10.244.0.0/16` and the date `2026.10.04` all match -- N.N.N is a prefix of
# N.N.N.N, and the equals and whole-line arms cannot tell an address from a
# version. Zero of these exist under .github today, which is why the scan is
# clean, but this is a multicast repo and `group=`/`src=`/`subnet=` is the
# idiomatic lowercase assignment in exactly the .github/scripts/ subtree now in
# scope. Not narrowed, because every narrowing (reject a 4th component, require
# a `v`) also drops a real reintroduction form; the $EXEMPT hatch absorbs it
# and the failure message names the hatch. Pinned by a probe so it is a
# measured limit rather than something rediscovered at red-build time.
#
# The equals arm is deliberately NOT the wider `[A-Za-z_]+[:=]` (colon too).
# That reds 30 correct lines, every one a `uses: owner/action@<sha> #
# version: vX.Y.Z` pin: `[^#]*` only blocks a `#` *after* the marker, and there
# the marker (`version:`) is itself inside the trailing comment. Those are tool
# pins, not fleet versions. Lowercase `description:` prose is skipped for the
# same reason -- examples, not values.
PATTERN='(default:|:[-=?]|[A-Z_]+[:=]|[A-Za-z_]+=)[^#]*v?[0-9]+\.[0-9]+\.[0-9]+|^[[:space:]"]*v?[0-9]+\.[0-9]+\.[0-9]+'

# Tool pins are not fleet versions and are correctly hardcoded. Keep this list
# short and explicit: adding to it should be a deliberate "is this a Talos or
# kernel version?" decision, not a reflex to turn the build green.
#
# Entries are matched against the whole name -- the filter below anchors with
# `[[:space:]]*[:=]`, so an entry must spell a variable's *full* name. A longer
# name sharing an entry's prefix is NOT covered: `CRANE_VER` does not match
# `CRANE_VERSION:`, because `SION` sits between the prefix and the `:`. Both
# names are live here for the same tool (crane), so both are spelled out.
# Alternate rather than reach for `CRANE_VER[A-Z_]*`: a prefix wildcard would
# silently adopt any future name starting CRANE_VER, which is exactly the
# undeliberate widening the paragraph above forbids.
ALLOW='CRANE_VER|CRANE_VERSION'

# A line that declares its literal is a fixture is exempt. Line-level, not
# file-level, and that is the whole design: the rest of the file stays scanned.
# It matters most in .github/scripts/, where the self-tests holding the
# fixtures sit in the same file as the production code most likely to grow a
# real literal -- a file-granular exclusion would blind exactly that.
#
# Chosen over the two alternatives in BLO-39887: an --exclude list is too
# coarse for the reason above, and moving fixtures to sibling testdata files
# would break the --self-test-in-one-file idiom this repo (and this script) is
# built on, while only relocating the literals rather than declaring them.
#
# Unlike $ALLOW this hatch is decentralized -- any line in any file can opt
# itself out, and the only control is that the diff shows it. So adding one is
# the same deliberate "is this a Talos or kernel version?" decision, not a
# reflex to turn the build green. A `default:` line is carved out of the hatch
# below: that is the exact surface this guard was written for (BLO-39684), and
# a marker there would re-open it with one trailing comment.
EXEMPT='#[[:space:]]*version-literal-ok'

# Scans a directory -- not a *.yml glob. 4 of this repo's 10 workflow files are
# .yaml, including the kres-generated ci.yaml, where a regenerated input default
# would land. Callers should hand it `.github`, not `.github/workflows`: the
# version-bearing logic now lives in `.github/scripts/` too.
#
# This file is excluded wholesale because its own probes below are literals by
# design. Everywhere else a literal is a hit unless its line carries $EXEMPT.
scan() {
  # A prose comment *about* a removed literal is not a literal. `[^#]*` in
  # PATTERN only blocks a `#` after the marker, so full-line comments are
  # dropped here.
  grep -rnE "$PATTERN" "$1" --exclude="$(basename "$0")" 2>/dev/null |
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' |
    grep -vE "($ALLOW)[[:space:]]*[:=]" |
    # "drop $EXEMPT lines unless they are a `default:`" needs a negative
    # lookahead, which ERE has not; awk is the one stage that can express it.
    # `grep .` is load-bearing -- awk always exits 0, and callers read scan's
    # exit status to mean "found something".
    #
    # Two things here are deliberate and both are mutation-pinned below:
    # - $EXEMPT is passed as *data* (-v), not spliced into program text. A `/`
    #   in the value would otherwise be a parse error, awk would die, `grep .`
    #   would see empty input and the scan would report a clean bill of health.
    #   A guard that fails open is worse than no guard.
    # - the carve-out matches the `:line:` field of grep -rn's
    #   `path:line:content` output, not a bare `default:`. Without that,
    #   `default:` anywhere on the line cancels the hatch -- including inside a
    #   plant payload, or in the prose explaining the exemption itself -- and
    #   the message then names a surface that is not there.
    #
    #   It is deliberately *not* `^`-anchored. `^[^:]*` cannot cross a colon,
    #   so a path containing one (`.github/a:b.yml`) slides `[0-9]+` onto the
    #   filename, the carve-out misses, and the line stays exempt: a `default:`
    #   literal silently waved through. Unanchored, the same path instead
    #   cancels its own marker -- a false positive, which is loud. The comment
    #   filter at :85 assumes the same output shape but is a *drop* filter, so
    #   it already fails in that safe direction; this stage had to be made to.
    #   Cost of the trade: a payload literally containing `:1: default:`
    #   cancels its own marker too. Fail-closed, so it stays.
    #
    # - `-?` covers the YAML sequence-item form. `- default:` is a PATTERN hit,
    #   so the guard already calls it in scope; without `-?` the carve-out did
    #   not, and the one key the carve-out exists to protect was the one a
    #   marker could re-open. Not a BLO-39684 surface -- `workflow_dispatch`
    #   and `workflow_call` inputs are mapping keys, never sequence items --
    #   but an internal inconsistency in a hatch is worth a character.
    awk -v ex="$EXEMPT" '$0 !~ ex || /:[0-9]+:[[:space:]]*-?[[:space:]]*default:/' |
    grep .
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

  # BLO-39887: lowercase is the idiom .github/scripts/ is written in, so these
  # two were the live hole -- the uppercase-only arm skipped them outright.
  probe "lowercase bare assignment" catch '          talos=v1.13.4' c.sh
  probe "lowercase, no v prefix"    catch '          kver=6.18.34' c.sh

  # The block-scalar form: the opener carries no version, so this is caught by
  # the whole-line arm on the continuation, not by the `default:` arm.
  probe "block-scalar continuation" catch '    default: >-
      v1.13.4'

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
  # The same tool under its other live name. $ALLOW is anchored to the end of
  # the name, so this is NOT covered by the CRANE_VER entry -- it needs its own.
  # This reds if the CRANE_VERSION alternative is dropped, which is how the
  # guard went red on main 86s after it landed (BLO-39887).
  probe "tool pin, longer name"   pass  '          CRANE_VERSION: v0.21.2'

  # Pins the BLO-39887 design decision: widening the equals arm to take a colon
  # too reds all 30 of these. If someone does, this goes red first.
  probe "pinned action trailing comment" pass \
    '      uses: owner/action@0f1e2d3c4b5a # version: v1.4.0'

  # The fixture-exemption mechanism. A declared literal is skipped...
  probe "declared fixture exempt"  pass \
    '          ver="v1.13.4" # version-literal-ok' c.sh
  # ...and only on its own line. Fails if the marker ever goes file-scoped.
  # The unmarked line uses the *uppercase* form on purpose, so this probe
  # tests EXEMPT alone and does not also depend on the new lowercase arm.
  probe "marker exempts only its line" catch \
    '          ver="v1.13.4" # version-literal-ok
          TAG=v1.13.4' c.sh
  # ...and never on a `default:`, the surface BLO-39684 was about. Fails if the
  # `|| /default:/` carve-out is dropped, which would let one trailing comment
  # re-open exactly what this guard exists to catch.
  probe "default: cannot be exempted" catch \
    "    default: 'v1.13.4' # version-literal-ok"
  # ...including as a YAML sequence item. The guard flags `- default:` as in
  # scope, so the hatch must refuse it too, or the one key carved out of the
  # hatch is re-openable by writing it one character differently. Fails if
  # `-?[[:space:]]*` is dropped from the carve-out.
  probe "- default: cannot be exempted either" catch \
    "    - default: 'v1.13.4' # version-literal-ok"
  # ...where "a `default:`" means the key, not the substring. Both of these
  # carry `default:` somewhere on the line and neither is a workflow default;
  # the second is the one that will actually bite, since explaining your own
  # exemption would cancel it. Fail if the carve-out loses its anchor.
  probe "default: inside a plant payload stays exempt" pass \
    '          plant a.yml "default: v1.13.4" # version-literal-ok' c.sh
  probe "default: in the exemption prose stays exempt" pass \
    '          TAG=v1.13.4 # version-literal-ok, replaces the old default:' c.sh
  # A colon in the *path* must not buy an exemption. `^[^:]*` cannot cross one,
  # so an anchored carve-out slides onto the filename, misses, and waves the
  # literal through -- silently, over the exact surface this guard exists for.
  # Unanchored it over-catches instead, which is loud. Fails if `^[^:]*` is
  # restored to the carve-out.
  probe "colon in the path cannot buy an exemption" catch \
    "    default: 'v1.13.4' # version-literal-ok" 'a:b.yml'
  # A measured limit, not an aspiration: N.N.N is a prefix of N.N.N.N, so an
  # address reads as a version. Declared here so the shape is known rather than
  # rediscovered on a red build. Goes red if the arms are ever narrowed -- at
  # which point delete this probe, do not re-widen to keep it green.
  probe "dotted quad is a known false positive" catch \
    '          group=239.1.1.1' c.sh
  probe "prose comment about a removed default" pass \
    '          # the old default: v1.13.4 was removed in BLO-39684'
  probe "description prose"       pass  "        description: 'image tag; defaults to the Pkgfile value'"
  probe "clean workflow"          pass  '    runs-on: ubuntu-latest'

  # $EXEMPT reaches awk as data, so a `/` in it is just a character. Spliced
  # into program text it is a parse error instead: awk dies, `grep .` sees
  # empty input, and the guard reports clean over a file that is not. probe()
  # cannot reach this -- it never varies $EXEMPT -- so assert it directly.
  # Fails if `-v ex=` is reverted to the interpolated form.
  rm -f "$d"/*
  printf '%s\n' "    default: 'v1.13.4'" > "$d/a.yml"
  rc=0; ( EXEMPT='#[[:space:]]*version-literal-ok/x'; scan "$d" >/dev/null ) || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "ok   a slash in \$EXEMPT does not zero the guard"
  else
    echo "FAIL a slash in \$EXEMPT does not zero the guard (awk likely died; scan found nothing -- its diagnostic is above)"
    fails=$((fails + 1))
  fi

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
      echo "^^ version literal above; declare it in Pkgfile and derive it (BLO-39684). A genuine test fixture can declare itself with a trailing '# version-literal-ok' -- except on a 'default:' line, which is the surface this guard exists for." >&2
      exit 1
    fi
    echo "no version literals in workflow defaults, fallbacks or env blocks"
    ;;
esac
