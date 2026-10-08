#!/usr/bin/env bash
# Fail when a ref that just DISPATCHED compose-signed-installer does not carry
# the Harbor promotion.
#
# BLO-39281. The promotion has now been ported onto a named branch three times
# in four days (#14 -> #21 -> #33), each time because the live signed-installer
# build line moved to a ref whose copy of compose-signed-installer.yml predated
# the previous port. Porting is not a fix for that: a fourth branch re-opens the
# hole, silently, and the tell is absent by construction -- a run that skips the
# promotion is `success`, publishes a perfectly good signed installer to ghcr,
# and differs from a correct run only in a registry nobody looks at until a node
# tries to pull.
#
# A workflow cannot guard its own ref: the dispatched ref supplies the workflow
# definition, so a ref lacking the promotion also lacks any check for it. The
# caller of this script is therefore triggered by `workflow_run`, which GitHub
# always runs from the DEFAULT branch regardless of which ref the triggering run
# was on. That is the one hook a stale ref cannot opt out of.
#
# Pure: every input is a file. No network, no registry, no credential -- the
# fetching is the caller's job, which keeps the decision testable.
#
# Both arms matter and they fail for different reasons:
#   invocation  the ref's workflow never calls the promotion script
#   identity    the ref's copy of the script has drifted from main's
#
# The identity arm is what buys the build branches the right NOT to carry the
# guard tests. Those tests and their failing mutations live on main, gate main's
# copy, and are meaningful for a branch only while that branch's copy is the
# same bytes. Checking that here is three lines; duplicating the test lane onto
# every build branch is a second thing to keep in sync, which is the defect this
# script exists to catch.
set -euo pipefail

usage() {
  echo "usage: $0 <ref-workflow> <ref-script> <canonical-script> <branch>" >&2
  echo "  ref-workflow      the ref's .github/workflows/compose-signed-installer.yml" >&2
  echo "  ref-script        the ref's .github/scripts/promote-installer-to-harbor.sh" >&2
  echo "  canonical-script  main's copy of the same script" >&2
  echo "  branch            the ref, for the failure message" >&2
  exit 2
}

[[ $# -eq 4 ]] || usage
REF_WORKFLOW=$1
REF_SCRIPT=$2
CANONICAL_SCRIPT=$3
BRANCH=$4

[[ -f "$CANONICAL_SCRIPT" ]] || {
  echo "canonical script not found at $CANONICAL_SCRIPT" >&2
  exit 2
}

# A missing or unreadable ref file reaches here as an empty file, and every
# check below treats empty as failing. That is deliberate: a fetch that returned
# nothing and a ref that genuinely carries nothing are the same answer for this
# guard's purpose, and the alternative -- treating an unreadable ref as "assume
# fine" -- is the failure direction that lets the hole through.
fail=0

if ! grep -q 'promote-installer-to-harbor\.sh' "$REF_WORKFLOW" 2>/dev/null; then
  echo "FAIL: $BRANCH dispatched compose-signed-installer, but its copy of" >&2
  echo "      .github/workflows/compose-signed-installer.yml never invokes" >&2
  echo "      .github/scripts/promote-installer-to-harbor.sh." >&2
  echo "" >&2
  echo "      A signed installer built on this ref is published to ghcr and" >&2
  echo "      NEVER mirrored into harbor.blockcast.net/library/talos-installer," >&2
  echo "      which is where the fleet's install.image is pinned. The run is" >&2
  echo "      green either way; the gap only surfaces when a node pulls." >&2
  echo "" >&2
  echo "      Port the promotion onto $BRANCH (see PR #33 for the shape), or" >&2
  echo "      rebase it on main." >&2
  fail=1
fi

if ! cmp -s "$REF_SCRIPT" "$CANONICAL_SCRIPT" 2>/dev/null; then
  echo "FAIL: $BRANCH's .github/scripts/promote-installer-to-harbor.sh is not" >&2
  echo "      byte-identical to main's." >&2
  echo "" >&2
  echo "      The promotion guards are tested, and mutation-tested, only on" >&2
  echo "      main. A build branch is allowed to carry the script without the" >&2
  echo "      test lane precisely because this check holds it to the copy those" >&2
  echo "      tests cover. A drifted copy is an untested guard." >&2
  echo "" >&2
  echo "      Edit it on main and re-copy, never in place on $BRANCH." >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "OK: $BRANCH carries the Harbor promotion, and its copy of the promotion script matches main"
