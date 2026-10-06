#!/bin/bash
# Self-check for the module-allowlist union step in
# .github/workflows/build-amt-installer.yml (BLO-40510).
#
# The rootfs module set comes from the TALOS tree; the kernel comes from the
# PKGS tree. Upstream moves them in lockstep, so pinning talos to the
# production release while overriding the kernel with a newer pkgs build
# splits a matched pair -- `depmod --errsyms` then fails the imager build on
# the first allowlisted driver that gained a dependency on a module the older
# allowlist never carried.
#
# Asserts the union is additive, complete for this pairing, and idempotent.
#   usage: hack/check-amt-allowlist-union.sh [checkout_ref] [paired_ref]
set -euo pipefail

CHECKOUT_REF="${1:-v1.14.0}"   # talos ref the workflow checks out
PAIRED_REF="${2:-v1.14.2}"     # talos ref whose PKGS pin matches pkgs_sha

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fetch() {
  curl -sSfL --retry 3 \
    "https://raw.githubusercontent.com/siderolabs/talos/$1/hack/modules-amd64.txt" -o "$2"
  test -s "$2" || { echo "allowlist from $1 is empty" >&2; exit 1; }
}
fetch "$CHECKOUT_REF" "$work/orig"
fetch "$PAIRED_REF"   "$work/paired"
cp "$work/orig" "$work/base"

# --- the workflow step's logic, verbatim ---
before=$(wc -l < "$work/base")
sort -u "$work/base" "$work/paired" -o "$work/base"
after=$(wc -l < "$work/base")
# -------------------------------------------

removed=$(comm -23 <(sort -u "$work/orig")   <(sort -u "$work/base"))
missing=$(comm -23 <(sort -u "$work/paired") <(sort -u "$work/base"))

# Additive: a union that dropped an entry would strip a NIC or disk driver from
# the rootfs and brick a node at boot. This is the property that matters most.
[ -z "$removed" ] || { echo "FAIL: union removed entries:"; echo "$removed"; exit 1; }
# Complete: every module the paired release allowlists is present.
[ -z "$missing" ] || { echo "FAIL: paired entries missing:"; echo "$missing"; exit 1; }
# The specific dependency that failed run 37423482220, and its dependent.
for m in kernel/drivers/net/macsec.ko \
         kernel/drivers/net/ethernet/aquantia/atlantic/atlantic.ko; do
  grep -qxF "$m" "$work/base" || { echo "FAIL: $m absent"; exit 1; }
done
# Idempotent: re-running the step must not drift the list.
sort -u "$work/base" "$work/paired" -o "$work/again"
cmp -s "$work/base" "$work/again" || { echo "FAIL: not idempotent"; exit 1; }

echo "PASS  ${CHECKOUT_REF} + ${PAIRED_REF}: ${before} -> ${after} lines, -0 removed"
comm -13 <(sort -u "$work/orig") <(sort -u "$work/base") | sed 's/^/  added: /'
