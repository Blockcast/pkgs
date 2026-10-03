# pkgs

> **Blockcast fork.** Upstream is [`siderolabs/pkgs`](https://github.com/siderolabs/pkgs).
> Read the next section before rebuilding anything that production boots.

## Which ref builds the production kernel

**`ci/talos-v1.14.0` is the authoritative source of the Talos kernel the
production AMT data nodes run. `main` is not, and must not be made into one.**

Upstream's release model is one branch per Talos minor (`release-1.13`,
`release-1.14`, …), and this fork inherited it. `main` tracks upstream `main`
plus the Blockcast overlay and is deliberately **not** version-pinned, so its
kernel version drifts freely — it reads **6.18.34** today while the fleet runs
**6.18.48**. A version-pinned production build belongs on a version branch; that
is what `ci/talos-v1.14.0` is. Merging it into `main` would produce a ref
matching neither upstream line and would pin `main` to Talos v1.14 forever.

Nor could `main` ever be made to agree in steady state: upstream `release-1.14`
is already at **6.18.54** against our pinned 6.18.48. Pinning is the point.

### Reconstruction recipe

If `ci/talos-v1.14.0` is ever deleted or force-moved, rebuild the production
kernel from these two facts — this recipe, not the branch name, is what makes
the build durable:

| | |
|---|---|
| upstream base | `siderolabs/pkgs` **`2f03590c50e45a9439a4b3abcdbe247693c179e0`** — an ancestor of `release-1.14`, i.e. it carries nothing of its own. Verify with `gh api repos/siderolabs/pkgs/compare/2f03590c...release-1.14 --jq .behind_by` → `0`. (Run in that direction: reversed it reports `ahead_by: 0`/`behind_by: 22`, the same fact read backwards.) |
| Blockcast overlay | **`1da0fb6f3684d2860ecfeab3115e7cd4388084d7`** — "build(talos): port the signed ct6 kernel and installer builds to v1.14.0" (Omar Ramadan, 2026-09-05), the branch tip and its *only* non-upstream commit |
| built by | `.github/workflows/build-ct6-mroute-kernel.yml`, `workflow_dispatch` |
| publishes | `ghcr.io/blockcast/kernel:v1.14.0-amt-ct6-mroute` |
| production build | [run 33968874224](https://github.com/Blockcast/pkgs/actions/runs/33968874224), success 2026-09-05, `head_sha=1da0fb6f3` |

That tag is the `OS-IMAGE` every Talos node reports (`Talos
(v1.14.0-amt-ct6-mroute)`, kernel `6.18.48-talos`).

### ⚠ Do not dispatch the ct6 build from `main` with a production tag

`build-ct6-mroute-kernel.yml` exists on **both** refs with correctly paired
defaults (`main` → `v1.13.4` / `6.18.34`; `ci/talos-v1.14.0` → `v1.14.0` /
`6.18.48`), so a *default* dispatch from `main` is harmless.

But `image_tag` and `kver` are validated **independently and never against each
other** — `image_tag` is only format-checked (`v[0-9]*.[0-9]*.[0-9]*-*`), while
`kver` is asserted against that ref's `kernel/build/config-amd64`. So a dispatch
from `main` passing `image_tag=v1.14.0-amt-ct6-mroute` with `kver=6.18.34`
satisfies both guards and **republishes production's tag from a 6.18.34
kernel**. The `amt.ko` built against 6.18.48 then fails to load on nodes running
that image (precedent: [`Blockcast/linux-amt@8806c2ad69`](https://github.com/Blockcast/linux-amt/commit/8806c2ad69),
in the *sibling* repo rather than this one — exec-format on v1.13.4).

Dispatch production builds from `ci/talos-v1.14.0`. See
[BLO-33964](https://paperclip.blockcast.net/BLO/issues/BLO-33964).

### Kernel-version agreement — enforced by `linux-amt`

`Blockcast/linux-amt` builds the `amt.ko` that must load into this kernel, so the two
must agree on a kernel version. **That agreement is enforced**, as **surface 8** of
`kernel/talos-extension/check-kver-drift.sh` in that repo — merged in
[`Blockcast/linux-amt#255`](https://github.com/Blockcast/linux-amt/pull/255) on
2026-10-03.

Surfaces 1–7 are local to `linux-amt` and only constrain what `amt.ko` is compiled
against; **8 is the only one that can see this repo**. It reads `pkgs_ref=` from
`kernel/talos-extension/PRODUCTION_KERNEL` — required, not optional: a missing key is
`exit 2`, never a silent skip — fetches this repo's `kernel/build/config-amd64` at that
ref, and fails CI when it disagrees with the declared fleet kernel. Before trusting it,
run the free negative control the script documents: setting `pkgs_ref=main` must make
the check fail. "surface 8" is also the search term for finding the right block of that
268-line script after a red run.

**If you move the authoritative ref, update `pkgs_ref` there in the same change.**
Otherwise that check goes red — or worse, keeps passing against a stale branch.

## Upstream: what this repo builds

![Dependency Diagram](/deps.svg)

This repository produces a set of packages that can be used to build a rootfs suitable for creating custom Linux distributions.
The packages are published as a container image, and can be "installed" by simply copying the contents to your rootfs.
For example, using Docker, we can do the following:

```docker
FROM scratch
COPY --from=<registry>/<organization>/<pkg>:<tag> / /
```

## Resources

- https://gcc.gnu.org/onlinedocs/gccint/Configure-Terms.html
- https://wiki.osdev.org/Target_Triplet
