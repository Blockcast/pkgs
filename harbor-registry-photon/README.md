# harbor-registry-photon: concurrent tag lookup

`goharbor/registry-photon:v2.14.0` with one change: the registry binary
(`/usr/bin/registry_DO_NOT_USE_GC`) is rebuilt from the exact
`goharbor/distribution` revision Harbor ships, plus a backport of
[distribution/distribution@a2afe23f38](https://github.com/distribution/distribution/commit/a2afe23f386e827d1975530aab12010f0be2a774)
("add concurrency limits for tag lookup and untag"). Everything else in the
image — entrypoint, user, healthcheck, volumes, the other files — is the stock
image, byte for byte.

Published as `ghcr.io/blockcast/harbor-registry-photon:v2.14.0-taglookup.2`
(`./build.sh --print-tag`). **Do not deploy `v2.14.0-taglookup.1`:** it was
published before deviation 1 below existed, so a cancelled manifest `DELETE`
can answer `202` and leave tags pointing at the deleted manifest.

## Why

Harbor garbage collection on `harbor.blockcast.net` (Harbor v2.14.0, storage =
S3 on Ceph RGW) takes days. Measured on GC run 2607, 2026-10-04: about 200
manifests deleted per hour with 5 GC workers, i.e. roughly 90 s per manifest
delete, while blob deletes take about 0.2 s. The slowest repositories are the
heavily tagged CI ones (`pim-multicast-gateway/{moq-relay,cast,moq-player-origin}`).

Root cause, in the registry rather than in Harbor: every manifest `DELETE`
calls `tagStore.Lookup` (`registry/handlers/manifests.go`, `DeleteManifest`) to
find the tags that point at the deleted digest, so it can untag them.
`Lookup` (`registry/storage/tagstore.go`) lists every tag in the repository and
then reads each tag's `current/link` **one at a time**. On S3 each read is a
round trip, so one manifest delete costs (tags in repo) x (S3 latency), and GC
deletes thousands of manifests from exactly the repos with the most tags.

Upstream distribution fixed this in a2afe23f38 (2024-04-26, released in v3).
Harbor never picked it up: Harbor v2.14.0 builds `goharbor/distribution`
branch `release/2.8`, and Harbor 2.15.3-rc2 still ships
`v2.8.3-harbor.2-rc.7` with the same serial loop. **Upgrading Harbor does not
fix this.**

## What the patch does

`patches/0001-*.patch`, against goharbor/distribution
`0c62ec3ec8df7ea91c819448236a67f0777f929f`:

- `tagStore.Lookup` reads tag links through an `errgroup` bounded by the tag
  store's concurrency limit. The first non-`PathNotFound` error cancels the
  remaining reads and fails the lookup, and so does a cancelled caller
  context — never a partial tag set.
- `DeleteManifest` untags the referencing tags through an `errgroup` bounded
  by `storage.DefaultConcurrencyLimit`.
- New `RegistryOption` `TagLookupConcurrencyLimit` and config key
  `storage.tag.concurrencylimit`. It must be a non-negative integer; anything
  else makes the registry panic at startup, exactly as upstream. Unset or `0`
  means `runtime.GOMAXPROCS(0)`.
- Vendors `golang.org/x/sync/errgroup` at v0.3.0 (`93782cc8`), the version
  upstream's `go.mod` pinned at a2afe23f38; `release/2.8` vendors with
  `vendor.conf` and had no `x/sync`, so it is added there too. Chosen over a
  hand-rolled worker pool so the code stays line-for-line comparable with
  upstream, which is what makes a future rebase or upstream sync mechanical.

**Two deliberate deviations from upstream.** Without them a manifest `DELETE`
can report success while tags still point at the deleted manifest.

1. **Cancelled request.** Upstream's `Lookup` shadows `ctx` with the
   errgroup's context and stops launching link reads once it is done;
   `g.Wait()` then returns nil and `Lookup` returns the tags read so far with
   no error. The handler's context is the request's, so a client disconnect or
   a jobservice timeout cancels it after `DeleteManifest` has already deleted
   the manifest; upstream then untags only that partial set. Two changes:
   - `Lookup` keeps the caller's context and, after `g.Wait()`, returns its
     error if it is done — never a partial set, for any caller.
   - `DeleteManifest` runs the tag lookup and untag that follow a successful
     manifest delete on `context.WithoutCancel(request context)`. Failing the
     request instead would not help: the manifest is already gone, the client
     that cancelled never sees the error, and Harbor GC retries the `DELETE`
     (`src/jobservice/job/impl/gc/garbage_collection.go`, v2.14.0), gets `404`
     and counts that as success — so every tag would be left pointing at the
     deleted manifest. Finishing the cleanup is also what the stock binary
     does on S3 in practice: this release's s3-aws driver calls the AWS SDK
     without the request context (`S3.GetObject`, `S3.ListObjects`,
     `S3.DeleteObjects`), so a disconnect does not stop it.
2. **Failed untag.** Upstream's concurrent untag loop assigns the collected
   errors to the response and then writes `202 Accepted` anyway. Here any
   `Untag` error means no `202`.

Not ported: upstream also added `tag: concurrencylimit: 8` to its example
config files and shows `8` in `docs/configuration.md`. That `8` has no
derivation: the example config files are left unchanged and the ported docs
show a placeholder, so the default stays `GOMAXPROCS`.

### Tests

Ported: upstream's `configuration` test for the `tag` section. Added:

| test | proves |
|---|---|
| `TestTagLookupMatchesSerial` | concurrent `Lookup` returns exactly the tag set of the verbatim serial algorithm, per digest, over `16 x limit` tags across 7 digests with every 5th tag's `current/link` removed (listed by `All()`, must be skipped) |
| `TestTagLookupConcurrencyIsBounded` | link reads reach exactly `limit` in flight and never exceed it; every read blocks until `limit` are in flight, so a serial implementation never completes |
| `TestTagLookupPropagatesStorageError` | a backend error on one tag fails the lookup and returns no partial result |
| `TestTagLookupCancelledContextFails` | deviation 1: a context cancelled before, or during, the lookup fails it with `context.Canceled` and no partial result |
| `TestTagLookupConcurrencyLimitOption` | unset/`0` → `GOMAXPROCS`; explicit value is used |
| `TestNewAppTagConcurrencyLimitConfig` | config validation: absent/0/positive accepted; string and negative panic |
| `TestDeleteManifestUntagsAllReferencingTags` | a manifest referenced by `4 x GOMAXPROCS + 1` tags deletes with 202 and leaves no referencing tag |
| `TestDeleteManifestUntagFailureFailsClosed` | deviation 2: failing untag → no 202 |
| `TestDeleteManifestCancelledRequestUntagsAll` | deviation 1: a `DELETE` whose request context is cancelled during the tag lookup still untags every referencing tag (`4 x GOMAXPROCS + 2` tags) and answers 202 |

Negative controls were run: with `Lookup` reverted to the serial loop the
bounded test never completes (`go test -timeout` fires); with upstream's
verbatim `imh.Errors = errs` + 202 the fail-closed test fails with "DELETE
returned 202 Accepted although every Untag failed"; with upstream's verbatim
`Lookup` all three cancellation tests fail (a partial or empty tag set with no
error, or tags still referencing the deleted manifest; the counts depend on
`GOMAXPROCS` and scheduling); with `Lookup` fixed but the handler's cleanup
still on the request context, the handler test fails with every tag left
referencing the deleted manifest.

The Dockerfile runs `go vet -printf=false` and `go test` on `configuration`,
`registry/storage` and `registry/handlers` (plus a `-race` pass of the new
tests) on every build. `go test` runs with `-vet=off` because go1.24's printf
check rejects pre-existing test code these packages already contain
(`registry/storage/purgeuploads_test.go:118`, `registry/handlers/api_test.go:888`).

## Pins

All inputs live in `release.env`; the Dockerfile has no defaults and
`build.sh` validates every value before building.

| value | source |
|---|---|
| `BASE_IMAGE` digest | image of container `registry` in the live `harbor/harbor-registry` Deployment. Single-arch `linux/amd64` manifest → `PLATFORM=linux/amd64` |
| `DISTRIBUTION_SHA` | the base binary's build info: `-X version.Revision=0c62ec3e…` |
| `DISTRIBUTION_DESCRIBE` | the base binary's `--version`: `v2.8.3-23-g0c62ec3e` (checked against `git describe` during the build) |
| `GOLANG_IMAGE` | the base binary's `go version -m`: `go1.24.6`, which is also Harbor v2.14.0's `GOBUILDIMAGE=golang:1.24.6`; pinned by index digest |
| Dockerfile frontend (`# syntax=` line) | `docker/dockerfile:1.27.1@sha256:4edf897a…`: the digest the floating `docker/dockerfile:1` resolved to in PR #19's CI run (37225451364), which is also `1.27.1`'s. The frontend parses and runs the whole build, so it is pinned like a base image. It lives in the `Dockerfile`, not `release.env`, because BuildKit reads it before any build arg exists |

The binary is built the way Harbor's `make/photon/registry/Dockerfile.binary`
builds it — GOPATH mode, `CGO_ENABLED=0`, `BUILDTAGS="include_oss include_gcs"`,
`make PREFIX=/go clean binaries` — with `VERSION` and `REVISION` overridden so
it identifies itself:

```
$ registry_DO_NOT_USE_GC --version
/usr/bin/registry_DO_NOT_USE_GC github.com/docker/distribution v2.8.3-23-g0c62ec3e+blockcast-taglookup.2
```

`REVISION` is `<DISTRIBUTION_SHA>+patch.sha256.<sha256 of the patch files>`.
The final stage replaces the binary with `harbor:harbor` / `0755` and fails the
build unless the owner/mode equal the base image's original and `--version`
reports the patched string.

## Build

```
./build.sh --print-tag   # the reference release.env defines
./build.sh --check       # build + tests + verification, publishes nothing
./build.sh --push        # also pushes; refuses if the tag already exists
```

`--push` never repoints a published tag: change anything here, bump
`PATCH_REVISION`. That includes the workflow file — a merge to `main` that
touches it re-runs `--push`, which stops on the existing tag and turns `main`
red. The one exception is this README: pushes and pull requests that change
only `README.md` do not trigger the workflow. CI (`.github/workflows/harbor-registry-photon.yaml`) runs
`--check` on pull requests whose head is in this repository (that keeps the
unmodified workflow off the privileged self-hosted runner for fork PRs, but a
fork PR can edit the workflow; the real control is the repo's fork-PR approval
policy, see the workflow header) and `--push` on `main`, in a separate
job that alone holds `packages: write`, and writes the pushed digest to the job
summary. Deploy by that digest, not by tag.

## Rolling it out — read before touching the Harbor config

1. **Roll the image first, with no config change.** The stock v2.14.0 binary
   rejects a config that contains `storage.tag` — it parses `tag` as a second
   storage driver (`must provide exactly one storage type. Provided:
   [<driver> tag]`) and exits. With no `tag` key the patched binary uses
   `GOMAXPROCS`; the live pod has no CPU limit, so that is the node's CPU count.
   **If a CPU limit is ever added to the registry pod, set
   `storage.tag.concurrencylimit` explicitly at the same time.** The binary is
   built with go1.24.6, whose `GOMAXPROCS` default is the host's CPU count and
   ignores cgroup CPU limits (container-aware `GOMAXPROCS` arrived in go1.25),
   and both bounds — tag lookup and untag (`storage.DefaultConcurrencyLimit`)
   — are computed once at startup, so a CPU limit lowers neither. The untag
   bound has no config key in upstream either.
2. Only once every `harbor-registry` replica runs the patched image, set
   `storage.tag.concurrencylimit` in the registry config if a bound other than
   `GOMAXPROCS` is wanted — derive it from what the RGW endpoint can absorb,
   not from upstream's example `8`.
3. **Rollback order is the reverse:** remove `storage.tag` from the config
   *before* going back to the stock image, or the stock binary will not start.
4. The image is pushed to ghcr; the cluster needs pull access to it (or the
   digest promoted into Harbor first). Note that `harbor-registry` pulling its
   own image from Harbor during its own rollout depends on the other replica
   staying up.

## Rebasing onto a future Harbor

1. Read the new `registry-photon` image's binary: `go version -m` on
   `/usr/bin/registry_DO_NOT_USE_GC` gives the Go version and
   `-X version.Revision=<sha>`; `--version` gives the describe string. Update
   `BASE_IMAGE` (by digest), `DISTRIBUTION_SHA`, `DISTRIBUTION_DESCRIBE`,
   `GOLANG_IMAGE` (by digest), `HARBOR_VERSION`; reset `PATCH_REVISION=1`.
2. Check whether that distribution revision already contains the fix: grep
   `registry/storage/tagstore.go` for `errgroup` / `concurrencyLimit`. If it
   does, retire this directory — that is the real exit.
3. Otherwise `git am patches/*.patch` onto the new SHA, resolve, run
   `go test -vet=off ./configuration/ ./registry/storage/ ./registry/handlers/`
   in the new Go image, regenerate with `git format-patch -1`, and replace the
   file in `patches/`.
4. `./build.sh --check`.
