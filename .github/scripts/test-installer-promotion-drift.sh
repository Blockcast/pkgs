#!/usr/bin/env bash
# Guards in check-installer-promotion-drift.sh (BLO-39281).
#
# Pure file-in/exit-code-out, so this needs no registry, no credential and no
# network -- which is the point of keeping the fetching in the workflow.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$here/check-installer-promotion-drift.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

canonical="$work/canonical.sh"
printf 'echo canonical promotion script\n' > "$canonical"

cp "$canonical" "$work/same.sh"
printf 'echo DRIFTED\n' > "$work/drifted.sh"
: > "$work/empty.sh"

printf 'steps:\n  - run: .github/scripts/promote-installer-to-harbor.sh --source "$OUT"\n' \
  > "$work/with-promotion.yml"
printf 'steps:\n  - run: docker push "$OUT"\n' > "$work/without-promotion.yml"
# A mention is not an invocation: a commented-out step and a `paths:` filter
# entry both name the script and neither runs it.
printf 'steps:\n  - name: Promote\n    # TODO re-enable: .github/scripts/promote-installer-to-harbor.sh "${args[@]}"\n    run: echo skipping promotion\n' \
  > "$work/commented-promotion.yml"
printf 'on:\n  push:\n    paths:\n      - .github/scripts/promote-installer-to-harbor.sh\n      - "src/**"\nsteps:\n  - run: docker push "$OUT"\n' \
  > "$work/paths-only-promotion.yml"
# A multi-line run block that calls the script from inside it must still pass.
printf 'steps:\n  - name: Promote\n    run: |\n      set -euo pipefail\n      .github/scripts/promote-installer-to-harbor.sh "${args[@]}"\n' \
  > "$work/block-promotion.yml"
: > "$work/empty.yml"

run() { "$script" "$1" "$2" "$canonical" some-branch >"$work/out" 2>"$work/err"; }

assert_ok() {
  local name=$1 wf=$2 sc=$3
  if ! run "$wf" "$sc"; then
    echo "EXPECTED PASS, GOT FAIL: $name" >&2
    cat "$work/err" >&2
    exit 1
  fi
  echo "ok: $name"
}

# Asserts the exit code AND that the failure names the right arm. A guard that
# fails for the wrong reason sends whoever reads the log to the wrong file.
assert_fails_naming() {
  local name=$1 wf=$2 sc=$3 needle=$4
  if run "$wf" "$sc"; then
    echo "EXPECTED FAIL, GOT PASS: $name" >&2
    exit 1
  fi
  if ! grep -q "$needle" "$work/err"; then
    echo "FAILED FOR THE WRONG REASON: $name (no '$needle' in stderr)" >&2
    cat "$work/err" >&2
    exit 1
  fi
  echo "ok: $name"
}

assert_ok "ref carries the promotion and the canonical script" \
  "$work/with-promotion.yml" "$work/same.sh"

assert_fails_naming "ref never invokes the promotion" \
  "$work/without-promotion.yml" "$work/same.sh" "never invokes"

assert_fails_naming "a commented-out promotion step is not an invocation" \
  "$work/commented-promotion.yml" "$work/same.sh" "never invokes"

assert_fails_naming "a paths: filter entry is not an invocation" \
  "$work/paths-only-promotion.yml" "$work/same.sh" "never invokes"

assert_ok "a call inside a multi-line run block is an invocation" \
  "$work/block-promotion.yml" "$work/same.sh"

assert_fails_naming "ref's copy of the promotion script has drifted" \
  "$work/with-promotion.yml" "$work/drifted.sh" "byte-identical"

assert_fails_naming "ref carries no promotion script at all" \
  "$work/with-promotion.yml" "$work/missing.sh" "byte-identical"

# An unreadable/404 fetch arrives as an empty file. It must fail, not pass:
# "I could not tell" and "it is fine" are the two answers this guard must never
# confuse, and only one of them lets an unmirrored installer through.
assert_fails_naming "unreadable workflow fetch reads as absent, not as fine" \
  "$work/empty.yml" "$work/same.sh" "never invokes"

assert_fails_naming "unreadable script fetch reads as drifted, not as fine" \
  "$work/with-promotion.yml" "$work/empty.sh" "byte-identical"

# Both arms report, rather than the first one short-circuiting the second --
# otherwise porting the workflow and leaving the script stale costs two rounds.
if run "$work/without-promotion.yml" "$work/drifted.sh"; then
  echo "EXPECTED FAIL, GOT PASS: both arms broken" >&2
  exit 1
fi
grep -q "never invokes" "$work/err" && grep -q "byte-identical" "$work/err" || {
  echo "both arms broken: only one was reported" >&2
  cat "$work/err" >&2
  exit 1
}
echo "ok: both arms report together"

# A missing canonical copy is a broken checkout, not a drifted ref. Exit 2
# keeps it distinguishable from a real finding.
if "$script" "$work/with-promotion.yml" "$work/same.sh" "$work/nope.sh" b 2>/dev/null; then
  echo "EXPECTED FAIL: missing canonical script" >&2
  exit 1
elif [[ $? -ne 2 ]]; then
  echo "missing canonical script must exit 2, not 1" >&2
  exit 1
fi
echo "ok: missing canonical script is a usage error, not a finding"

echo "all checks passed"
