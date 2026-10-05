# pkgs

Blockcast's Talos package and signed-installer build source. **Use `main` for
new builds.** It consolidates the former `ci/talos-v1.14.0` production line
with the build guards, Harbor promotion, and registry fixes maintained on main.

The build pairing lives in `Pkgfile`: Talos **v1.14.0**, Linux **6.18.48**.
Kernel dispatches derive their tag from that pairing. Installer dispatches
require explicit matching inputs; for a ct6 base, pass the extension explicitly:
`ghcr.io/blockcast/amt-kmod:v1.14.0`. Use fresh output tags for rebuilds;
Harbor promotion refuses to overwrite an existing different digest by default.

The build sequence is `build-ct6-mroute-kernel.yml`, `build-amt-installer.yml`,
then `compose-signed-installer.yml`, all dispatched from `main`. The last step
publishes the SecureBoot installer and promotes it into
`harbor.blockcast.net/library/talos-installer`. A source merge does not upgrade
nodes. `Blockcast/linux-amt/kernel/talos-extension/PRODUCTION_KERNEL` tracks
the fleet pairing; its `pkgs_ref` must switch to `main` after this consolidation
lands, keeping the cross-repo drift check on the active build line.

The historical production kernel remains reproducible from upstream
`siderolabs/pkgs@2f03590c50e45a9439a4b3abcdbe247693c179e0` plus Blockcast
commit `1da0fb6f3684d2860ecfeab3115e7cd4388084d7` (Linux 6.18.48):
[kernel build 33968874224](https://github.com/Blockcast/pkgs/actions/runs/33968874224).
`ci/talos-v1.14.0` is retained as a historical ref, not a second maintenance line.
That build published kernel digest
`sha256:5017486d17b0667a2a00d9262cc34198045512cd97df29a0fe55d0557abf0623`.

Upstream updates for this Talos minor come from `siderolabs/pkgs:release-1.14`.
Upstream `main` is already on v1.15 development. The inspected release-1.14 tip
`6c312e4b77817a9c1bd4975a532b3fd23d33430c` moves Linux to 6.18.54; that upgrade
needs a matching AMT extension rebuild and a validated rollout. Keep it separate
from this source consolidation so the deployed kernel pairing stays explicit.

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
