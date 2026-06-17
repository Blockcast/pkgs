| Patch file                                                                 | Description                                | Upstream status | Link                                                                                                                                                                                                         |
|----------------------------------------------------------------------------|--------------------------------------------|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0001-net-macb-flush-PCIe-posted-write-after-TSTART-doorbe.patch`           | macb: flush PCIe posted write after TSTART doorbell (silent TX stall on BCM2712/RP1)                            | RFC submitted to netdev | [lore thread](https://lore.kernel.org/netdev/cover.1777064117.git.lukasz@raczylo.com/T/)                                                                                                              |
| `0002-net-macb-re-check-ISR-after-IER-re-enable-in-macb_tx.patch`           | macb: re-check ISR after IER re-enable in `macb_tx_poll()` to catch TCOMP raised inside the IDR/IER mask window | RFC submitted to netdev | [lore thread](https://lore.kernel.org/netdev/cover.1777064117.git.lukasz@raczylo.com/T/)                                                                                                              |
| `0003-net-macb-add-TX-stall-watchdog-as-defence-in-depth-s.patch`           | macb: per-queue `delayed_work` watchdog that calls `macb_tx_restart()` if `tx_tail` hasn't advanced for ≥ 1 s   | RFC submitted to netdev | [lore thread](https://lore.kernel.org/netdev/cover.1777064117.git.lukasz@raczylo.com/T/)                                                                                                              |
| `0004-PCI-prevent-shrink-bridge-window.patch`                               | PCI: prevent `adjust_bridge_window()` from shrinking a bridge window below the size required by `pbus_size_mem()` — fixes large-BAR / eGPU resource starvation                                                | Merged to mainline v6.19, candidate for 6.18.y stable backport | [lore patch](https://patch.msgid.link/20260219153951.68869-1-ilpo.jarvinen@linux.intel.com)                                                                                                            |
| `0005-PCI-fix-premature-removal-realloc-head.patch`                         | PCI: reorder checks in `reassign_resources_sorted()` so entries aren't dropped from `realloc_head` before being processed — preserves `add_size` for deeper PCI hierarchy levels                              | Merged to mainline v6.19, candidate for 6.18.y stable backport | [lore patch](https://patch.msgid.link/20260313084551.1934-1-ilpo.jarvinen@linux.intel.com)                                                                                                            |

## Blockcast AMT (in-tree source overlay — NOT a patch)

The Blockcast AMT relay driver is no longer applied as a `diff -u` patch. The
former `0006-amt-blockcast-oot.patch` touched only `drivers/net/amt.c` and so
silently dropped the matching AMT header changes (`include/net/amt.h`,
`include/uapi/linux/amt.h`) — it failed to compile against the stock 6.18.29
headers. It is replaced by a deterministic three-file overlay committed under
`kernel/build/blockcast-amt/` and `cp`-ed over the vanilla in-tree files by
`kernel/build/pkg.yaml` (after the patch loop, before `make`). Built in-tree as
`CONFIG_AMT=m` so the kernel auto-signs `amt.ko` (`CONFIG_MODULE_SIG_ALL`) and
trusts it under `module.sig_enforce=1`. Source of truth:
[linux-amt@feat/amt-6.18-canonical](https://github.com/Blockcast/linux-amt/tree/feat/amt-6.18-canonical).
