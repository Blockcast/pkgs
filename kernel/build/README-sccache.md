# sccache object cache for the ct6 kernel build

The kernel compile (`build-ct6-mroute-kernel.yml`) is a cache-cold full clang
build (~2h20m) every time `config-amd64` changes, because bldr's BuildKit
**layer** cache is all-or-nothing: any edit to the compile layer's inputs busts
the whole layer. sccache adds an **object**-level cache so config-only rebuilds
reuse unchanged `.o` files (minutes, not hours).

## Why it's shaped this way

- **bldr v0.6.0 exposes no BuildKit cache/secret mount** for pkg steps, and the
  `chromium-build` ARC runner's DIND is ephemeral (emptyDir) — so a cache that
  survives across runs must be **remote** (S3), reached over the LAN from inside
  the BuildKit RUN.
- Backend: **ceph-rgw S3** (the same store behind `gha-cache.blockcast.net`).
- **Gated + fail-safe.** The compile only wraps `CC="sccache clang"` when
  kernel-build receives `--build-arg=SCCACHE_S3_BUCKET=…`. Without it the build
  is byte-identical to before. sccache is transparent (bit-identical output vs
  plain clang) and falls back to a direct compile on any backend error, so it
  can never break or regress the build — worst case is a cache miss (today's
  speed).
- Secret S3 keys travel as a **scrubbed context file** (`certs/sccache.env`),
  never a build-arg (which would persist in image metadata).

## Activation (one-time)

1. Provision a bucket on ceph-rgw (e.g. `amt-kernel-sccache`) + an S3 keypair
   scoped to it.
2. Add repo/org secrets: `SCCACHE_S3_BUCKET`, `SCCACHE_S3_ENDPOINT`,
   `SCCACHE_S3_ACCESS_KEY_ID`, `SCCACHE_S3_SECRET_ACCESS_KEY`
   (+ optional var `SCCACHE_S3_USE_SSL`, default `true`).
3. Dispatch `build-ct6-mroute-kernel` once as a **validation build**: confirm the
   "Configure sccache" step prints `configured`, the build succeeds, and
   `sccache --show-stats` shows cache writes. The first build is a full miss
   (populates the cache); the next config-only change should be minutes.

## The one unverified assumption

Whether a bldr BuildKit RUN container can reach the rgw endpoint. If it can't,
sccache logs the error and falls back to direct compile (build stays green, just
no speedup) — check `sccache --show-stats` in the build log to confirm hits.
