#!/usr/bin/env bash
# Print the kernel arguments to bake into the signed UKI, one per line, from
# $EXTRA_KARGS (the compose-signed-installer `extra_kernel_args` input,
# space-separated).  Empty or unset prints nothing and succeeds.
#
# The input is DATA from a workflow_dispatch form: it reaches this script
# through an env var (never interpolated into shell), and every token must be a
# plain kernel argument.  A token that is not is refused rather than fixed up,
# because the result is baked into a Secure Boot signed image.
#   - first character alphanumeric (so it can never read as an imager flag)
#   - then only letters, digits and  . _ : , / + = -
#   - at most 128 characters per token, at most 16 tokens, duplicates collapse
set -euo pipefail
export LC_ALL=C   # [A-Za-z0-9] below means ASCII only, whatever the caller's locale

raw="${EXTRA_KARGS:-}"
# A newline would smuggle a second token past a per-line reader; refuse it.
case "$raw" in *$'\n'*|*$'\r'*) echo "extra_kernel_args must be one line of space-separated arguments" >&2; exit 1;; esac

# `read -ra` splits on blanks only: an unquoted `for tok in $raw` would also
# expand * ? [ ] against the working directory (the repo root in the workflow).
read -ra toks <<< "$raw"

declare -A seen=()
out=()
for tok in "${toks[@]+"${toks[@]}"}"; do
  if [ "${#tok}" -gt 128 ]; then echo "kernel argument longer than 128 characters refused" >&2; exit 1; fi
  if ! [[ "$tok" =~ ^[A-Za-z0-9][A-Za-z0-9._:,/+=-]*$ ]]; then
    echo "kernel argument refused (allowed: start with a letter or digit, then letters digits . _ : , / + = -): $tok" >&2
    exit 1
  fi
  [ -n "${seen[$tok]:-}" ] && continue
  seen[$tok]=1
  out+=("$tok")
  if [ "${#out[@]}" -gt 16 ]; then echo "more than 16 extra kernel arguments refused" >&2; exit 1; fi
done
# Print only after EVERY token passed: a caller reading stdout must never see a
# partial list from a refused input.
[ "${#out[@]}" -eq 0 ] || printf '%s\n' "${out[@]}"
