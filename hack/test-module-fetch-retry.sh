#!/usr/bin/env bash
# BLO-37661: assert the `network: default` prepare blocks retry a transient
# module fetch instead of failing the build on the first fault.
#
# flannel-cni/pkg.yaml and tc-redirect-tap/pkg.yaml are otherwise byte-identical
# to siderolabs/pkgs upstream, so an upstream sync can silently drop the retry.
# Run this by hand after any sync; it is deliberately not wired into CI because
# ci.yaml is kres-generated and a hand-added job would not survive `make rekres`.
#
# Verified to have a failing mutation: run it against the upstream (un-retried)
# blocks and the faults=1 case goes red.
set -euo pipefail
cd "$(dirname "$0")/.."

# pkg.yaml carries Go templates and is not parseable YAML -- extract by line range.
extract() {
  awk '/^  - network: default$/{f=1;next} f&&/^  - network:/{exit} f&&/^      - \|$/{g=1;next} g{sub(/^        /,"");print}' "$1"
}

run_case() { # $1=script $2=fault_count $3=expected_exit
  local d n got
  d=$(mktemp -d); trap 'rm -rf "$d"' RETURN
  printf '#!/bin/sh\nn=$(cat %s/n); n=$((n+1)); echo $n > %s/n\n[ $n -le %s ] && exit 1\nexit 0\n' "$d" "$d" "$2" > "$d/go"
  printf '#!/bin/sh\nexit 0\n' > "$d/tar"
  printf '#!/bin/sh\nexit 0\n' > "$d/sleep"   # keep the check instant
  chmod +x "$d/go" "$d/tar" "$d/sleep"; echo 0 > "$d/n"
  got=0; ( export PATH="$d:$PATH"; set -e; eval "$1" ) >/dev/null 2>&1 || got=$?
  n=$(cat "$d/n")
  [ "$n" -gt 0 ] || { echo "  FAIL extracted script never invoked go"; return 1; }
  [ "$got" = "$3" ] || { echo "  FAIL faults=$2 -> exit $got, want $3 (go invoked ${n}x)"; return 1; }
  echo "  ok   faults=$2 -> exit $got, go invoked ${n}x"
}

for f in flannel-cni/pkg.yaml tc-redirect-tap/pkg.yaml; do
  echo "== $f"
  script=$(extract "$f")
  [ -n "$script" ] || { echo "  FAIL extracted nothing from $f"; exit 1; }
  run_case "$script" 0 0   # clean run
  run_case "$script" 1 0   # one transient fault -- the run 36368015537 case
  run_case "$script" 2 0   # third attempt wins
  run_case "$script" 9 1   # a persistent fault must STILL fail the build
done
echo "ALL PASS"
