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
#
# The same anchoring is needed on the *left*, and the filter below spells it
# `(^|[^-.A-Za-z0-9_])` rather than leaving the alternation bare. Unanchored, a
# name merely *ending* in an entry was adopted as the pin -- `MY_CRANE_VER:`
# and `XCRANE_VERSION:` both went silently clean -- which is the mirror image
# of the prefix wildcard this paragraph declines. `-` and `.` are in the class
# because the names here are not only shell names: a shell name is word
# characters only, but a YAML key may hold either, so `FOO-CRANE_VER:` is a
# reachable name and `[^A-Za-z0-9_]` alone would still adopt it. One probe per
# character below, same as the value class.
#
# The filter is token-scoped, not line-scoped: it redacts each pin *and its
# value* and re-tests what is left, so a real literal sharing a physical line
# with a pin still reds. A `grep -v` over the line dropped the whole line once
# any entry appeared on it -- a fail-open, since the suppression was wider than
# the thing it suppressed (BLO-40232). Nothing in .github wrote two assignments
# on one line, so this was never live; pinned by a probe rather than left to be
# rediscovered on a red build, which is how the dotted-quad limit above is
# handled too.
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
    # Redact every $ALLOW pin and its value, then re-test the remainder against
    # PATTERN. Dropping the whole line instead let a genuine literal ride along
    # on a pin's line (BLO-40232). The value has to go with the name: strip
    # `CRANE_VER=` alone and the bare `"v0.20.2"` left behind matches PATTERN's
    # whole-line arm, so the pin would red itself.
    #
    # `[^[:space:],;&|{}]*` is the value: unquoted or quoted, both end at
    # whitespace. The separator classes are the point -- bounding only at
    # whitespace made the value greedy across any *other* separator, so
    # `CRANE_VER=v0.20.2;TALOS=v1.13.4`, the `&&` form and the YAML flow
    # mapping `{CRANE_VER: v0.20.2,TALOS: v1.13.4}` each redacted the real
    # literal along with the pin and went silently clean: the same fail-open,
    # one separator over, as the line-scoped `grep -v` this stage replaced
    # (BLO-40232). A pin value contains none of these characters, so bounding
    # at them costs nothing. The comma form happened to red anyway -- the
    # greedy value stopped at the space before the second value, leaving it
    # alone on the remainder for the whole-line arm -- but that rescue
    # vanishes inside `{...}`, which is why it is not evidence of coverage.
    #
    # The set is "separators that are valid in YAML or in shell", which is the
    # whole realistic surface: every form a pin and a literal can actually
    # share a line in this repo routes through one of these six. It is not the
    # set of all ASCII punctuation. `)`, `]` and `"` each still fail open --
    # `(CRANE_VER=v0.20.2)TALOS=v1.13.4` reads clean -- but every shape that
    # reaches them is neither valid YAML nor valid shell. Stated so the
    # boundary is falsifiable: a counter-example that parses is a bug report.
    #
    # An *absent* value (a YAML key whose value is on the next line) redacts
    # fine, but the continuation line carries no pin token at all, so
    # redaction there is a no-op and the whole-line arm flags it: `CRANE_VER:`
    # over two lines reds today. Loud, pre-existing, and $EXEMPT absorbs it.
    #
    # The match is greedy and could in principle eat a `#` and the comment
    # after it, but PATTERN's `[^#]*` already refuses to look past a `#`, so
    # nothing downstream reads what it ate.
    #
    # PATTERN arrives through the environment, not `-v`: `-v` runs escape
    # processing over the value, and the three `\.` here are undefined escapes,
    # which implementations are free to handle differently. ENVIRON does no
    # processing at all, so the regex reaches awk byte-for-byte whatever awk
    # this is. UNPINNED: mawk 1.3.4, the awk on this runner, passes `\.`
    # through `-v` unchanged, so no probe below can tell the two apart here and
    # reverting to `-v` is a surviving mutation. Kept because it costs one
    # token and removes the question; not kept on the strength of a measured
    # failure, which is why this says so rather than claiming a probe covers
    # it (BLO-40232).
    #
    # The redact and the re-test both run on the *content*, with grep -rn's
    # `path:line:` prefix stripped off first. PATTERN's whole-line arm is
    # `^`-anchored, and against the prefixed string that anchor can never fire,
    # so `v1.13.4 CRANE_VER: v0.20.2`
    # would read clean. When the prefix will not parse -- `^[^:]*` cannot cross
    # a colon in the path -- the line is kept rather than re-tested: a false
    # positive is loud, and a guard that fails open is worse than no guard.
    # That is the same trade, in the same direction, as the carve-out below.
    # The claim is fail-closed, not total: a path containing `:<digits>:` makes
    # the strip succeed on the *wrong* colon, leaving content the `^` arm can
    # no longer match. Left to the comment rather than the code -- `a:12:b.yml`
    # is absurd as a filename, and the narrower the path test the more ordinary
    # paths it fails on.
    #
    # The `(^|[^-.A-Za-z0-9_])` that anchors the name on the left is part of the
    # match, so the gsub eats that one leading character along with the pin.
    # That is why the strip has to run *first*: against the prefixed string the
    # character before a column-0 pin is the `path:line:` prefix's own trailing
    # colon, the gsub eats it, the strip then fails and the fail-closed arm reds
    # a correct tool pin -- with a message telling the author to move it to
    # Pkgfile, which is wrong advice for one. Stripping first also makes the `^`
    # alternative mean what it reads as; against the prefix it could never fire.
    # On the content the eaten character is always a separator -- a word
    # character there is what the anchor refuses -- and dropping one cannot turn
    # a hit into a miss. Three of the four alternatives opening $PATTERN's first
    # arm start at a word character, and its second arm is `^`-anchored over
    # leading whitespace; `:[-=?]` is the one that opens on a separator, and its
    # colon can never *be* the eaten character. The eaten one is whatever
    # immediately precedes an $ALLOW name, every entry starts `[A-Za-z]`, and
    # that arm requires `[-=?]` next -- disjoint sets, so the colon it needs is
    # never the one consumed. Measured: `${x:-v1.13.4}CRANE_VER=v0.20.2` reds
    # (probed below), as does `A=${B:-v1.13.4} CRANE_VER=v0.20.2`, while the
    # real pin `${CRANE_VER:-v0.20.2}` stays clean.
    # `TALOS=v1.13.4,CRANE_VER=v0.20.2` loses the comma and still reds.
    PAT="$PATTERN" AL="$ALLOW" awk '
      BEGIN {
        pat = ENVIRON["PAT"]
        pin = "(^|[^-.A-Za-z0-9_])(" ENVIRON["AL"] ")[[:space:]]*[:=][[:space:]]*[^[:space:],;&|{}]*"
      }
      {
        rest = $0
        if (!sub(/^[^:]*:[0-9]+:/, "", rest)) { print; next }
        gsub(pin, "", rest)
        if (rest ~ pat) print
      }' |
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
  # The same pin unindented, which is the idiom in shell. Covers two things at
  # once, both of which this guard got wrong before: the strip has to run
  # before the gsub, or the character the left-anchor eats here is the
  # `path:line:` prefix's own colon and a correct pin reds; and the `^`
  # alternative in that anchor only reaches position 1 once the prefix is gone,
  # so without this probe deleting `^|` is a surviving mutation.
  probe "tool pin at column 0"    pass  'CRANE_VER=v0.20.2' c.sh
  # The same tool under its other live name. $ALLOW is anchored to the end of
  # the name, so this is NOT covered by the CRANE_VER entry -- it needs its own.
  # This reds if the CRANE_VERSION alternative is dropped, which is how the
  # guard went red on main 86s after it landed (BLO-39887).
  probe "tool pin, longer name"   pass  '          CRANE_VERSION: v0.21.2'
  # ...and the other end of the same anchoring. A name that merely *ends* in an
  # entry is not that tool's pin, so its value is a fleet literal and must red.
  # Goes red if `(^|[^-.A-Za-z0-9_])` is dropped from the pin regex: the bare
  # alternation matches mid-name and the line is redacted away silently. The
  # probe above is the positive control -- the real pins must stay quiet.
  probe "name merely ending in a pin's name" catch \
    '          MY_CRANE_VER: v1.13.4'
  # The separator the left-anchor eats is never load-bearing for a $PATTERN
  # match. `:[-=?]` is the only opening alternative that starts on a separator,
  # and its colon cannot be the eaten one -- the eaten character precedes an
  # $ALLOW name, every entry starts `[A-Za-z]`, and this arm needs `[-=?]`
  # there. So the shell default keeps its colon and still reds with a real pin
  # butted against it, having lost only the `}`.
  #
  # Lowercase `x` is load-bearing: with `X` the leftover `X:` also matches the
  # `[A-Z_]+[:=]` arm, so the probe would red for the wrong reason and stop
  # isolating this one. As written it is the only probe that reds when
  # `:[-=?]` is dropped from $PATTERN -- that arm was carrying no probe at all
  # before this, i.e. it was a surviving mutation in the suite.
  probe "separator eaten next to a colon arm" catch \
    '${x:-v1.13.4}CRANE_VER=v0.20.2' c.sh
  # The two non-word name characters, one probe each: a YAML key may hold `-`
  # or `.` where a shell name may not, so leaving either out of the anchor
  # class re-opens the miss above for that character alone.
  probe "hyphenated name ending in a pin's name" catch \
    '          FOO-CRANE_VER: v1.13.4'
  probe "dotted name ending in a pin's name" catch \
    '          foo.CRANE_VER: v1.13.4'
  # BLO-40232: the pin is scoped to its own token, so a real literal sharing
  # the line still reds. Goes red if the redact-and-re-test awk is reverted to
  # a `grep -v` over the line -- the fail-open this probe exists for. The
  # `env:` probe above is the positive control for it: `TALOS: v1.13.4` alone
  # was already caught, so a pass here is scoping and not blanket suppression.
  probe "literal riding on a pin's line" catch \
    '          CRANE_VER: v0.20.2 TALOS: v1.13.4'
  # ...and the pin itself is still not the thing reported. Both orders, because
  # the redaction is a gsub over the line and must not depend on which comes
  # first. Goes red if the value stops being redacted with the name: the bare
  # `v0.20.2` left behind is a whole-line-arm hit all by itself.
  probe "pin after the literal still reds" catch \
    '          TALOS: v1.13.4 CRANE_VER: v0.20.2'
  probe "two pins on one line stay quiet" pass \
    '          CRANE_VER=v0.20.2 CRANE_VERSION=v0.21.2' c.sh
  # The pin's *value* is bounded at the separators a version cannot contain,
  # not just at whitespace. One probe per *character*, not per family: measured
  # per-character, a probe only ever pins the one separator it actually
  # contains, so the two-probe "covers `{`/`,`/`}` and `;`/`&`/`|`" split this
  # replaces left four of the six free -- dropping `&`, `|`, `{` or `}` alone,
  # or narrowing the whole class to `[^[:space:],;]*`, was 36/36 green while
  # the `&&` and `|` forms went silently clean again. Each probe below reds
  # when its own character is dropped from the class, and nothing else does.
  # The first four shapes are the realistic ones and all four were silently
  # clean before BLO-40232's second pass: the greedy value swallowed the
  # separator and the real literal with it.
  probe "literal after a pin in a flow mapping" catch \
    '      env: {CRANE_VER: v0.20.2,TALOS: v1.13.4}'
  probe "literal after a pin past a shell separator" catch \
    '          CRANE_VER=v0.20.2;TALOS=v1.13.4' c.sh
  probe "literal after a pin past &&" catch \
    '          CRANE_VER=v0.20.2&&TALOS=v1.13.4' c.sh
  probe "literal after a pin past a pipe" catch \
    '          CRANE_VER=v0.20.2|TALOS=v1.13.4' c.sh
  # The last two are the *only* shapes that pin `{` and `}`: a brace has to
  # fall immediately after a value to bound it, which rules out the flow
  # mapping above (its `{` sits before the pin name, and in `v0.20.2{x}` the
  # `}` bounds first). Both are shell, and both are legal-but-unidiomatic
  # there -- measured, `sh -n` accepts each as a single assignment word. The
  # close-brace fixture was written as YAML (`{CRANE_VER: v0.20.2}TALOS:
  # v1.13.4`) and is *not* valid YAML -- go-yaml (yq v4.44.3) rejects it with
  # "did not find expected key", trailing content after a flow mapping -- so
  # the claim and the fixture disagreed. Moved to shell rather than softened in
  # prose: the
  # shape still pins `}`, and now the one word covering both halves is one
  # that was measured for both. Kept as probes rather than as an UNPINNED note
  # because a one-line fixture that reds is cheaper than a paragraph claiming
  # the character is unreachable -- which is what the per-character sweep
  # above disproved.
  probe "literal after a pin past an open brace" catch \
    '          CRANE_VER=v0.20.2{TALOS=v1.13.4' c.sh
  probe "literal after a pin past a close brace" catch \
    '          CRANE_VER=v0.20.2}TALOS=v1.13.4' c.sh
  # The re-test has to see the content, not grep -rn's `path:line:` prefix.
  # This line's literal is caught only by PATTERN's `^`-anchored whole-line
  # arm, so it is the one shape that needs the prefix stripped off first. Goes
  # red if `sub(/^[^:]*:[0-9]+:/, ...)` is dropped from the re-test.
  probe "literal at line start, pin after it" catch \
    '      v1.13.4 CRANE_VER: v0.20.2'
  # ...and when the prefix cannot be found at all, the line is kept. Same path
  # shape as the exemption probe further down, but with a pin on the line, so
  # it reaches this stage's fail-closed arm instead. Goes red if the strip is
  # made unconditional: the `^` arm then never fires and the literal is waved
  # through silently, which is the one direction this guard must not fail in.
  probe "colon in the path keeps a pin line" catch \
    '      v1.13.4 CRANE_VER: v0.20.2' 'a:b.yml'
  # The remainder is re-tested against PATTERN verbatim, so a dotted-looking
  # non-version on a pin line must stay quiet. This does NOT pin the ENVIRON
  # choice: under mawk, `-v` delivers `\.` unchanged and this still passes.
  # See the UNPINNED note at the awk stage.
  probe "pin line with a non-version dotted-looking value" pass \
    '          CRANE_VER: v0.20.2 FOO=1x2x3' c.sh

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
