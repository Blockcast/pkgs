# Blockcast in-tree AMT source overlay

These three files are the canonical Blockcast AMT relay driver, copied verbatim
from [`Blockcast/linux-amt@feat/amt-6.18-canonical`](https://github.com/Blockcast/linux-amt/tree/feat/amt-6.18-canonical)
(`kernel/...`). They are `cp`-ed over the vanilla linux-6.18.29 in-tree files by
`kernel/build/pkg.yaml` (after the patch loop, before `make`), so `CONFIG_AMT=m`
builds the Blockcast driver in-tree (auto-signed by the kernel's own
`CONFIG_MODULE_SIG_ALL` key, trusted under `module.sig_enforce=1`).

| Overlay file (`/pkg/blockcast-amt/`) | In-tree destination (`/src/`)    | vanilla 6.18.29 |
|--------------------------------------|----------------------------------|-----------------|
| `amt.c`                              | `drivers/net/amt.c`              | replaced        |
| `net-amt.h`                          | `include/net/amt.h`             | replaced        |
| `uapi-amt.h`                         | `include/uapi/linux/amt.h`      | replaced        |

All three paths already exist in vanilla 6.18.29; the overlay overwrites them in
place, so no `Kbuild`/`Makefile` registration is required. The canonical files
are strict supersets of the vanilla 6.18.29 originals (additive AMT extensions:
`IFLA_AMT_LOCAL_IP6`, `IFLA_AMT_HASH_BUCKETS`, `IFLA_AMT_MAX_GROUPS`,
`IFLA_AMT_NUM_QUEUES`, v6-relay groups_rhl / rhltable, etc.).

This replaces the former `kernel/build/patches/0006-amt-blockcast-oot.patch`,
which patched only `amt.c` and therefore dropped the header changes — it failed
to compile against the stock 6.18.29 headers. The three-file set is proven
self-contained by the `linux-amt` Talos extension build
(`kernel/talos-extension/Dockerfile`, `COPY drivers ./drivers` + `COPY include
./include`), which compiles `amt.ko` without touching `if_link.h`.

To re-sync after an upstream `linux-amt` change:

```sh
git -C ~/src/linux-amt show feat/amt-6.18-canonical:kernel/drivers/net/amt.c        > amt.c
git -C ~/src/linux-amt show feat/amt-6.18-canonical:kernel/include/net/amt.h        > net-amt.h
git -C ~/src/linux-amt show feat/amt-6.18-canonical:kernel/include/uapi/linux/amt.h > uapi-amt.h
```
