# syntax=docker.io/docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom
#
# Harbor registry-photon with distribution/distribution a2afe23f38 (concurrent,
# bounded tag lookup + untag) backported onto the exact goharbor/distribution
# revision the base image ships. Build with ./build.sh, which supplies every
# ARG from release.env; there are deliberately no defaults here.

ARG GOLANG_IMAGE
ARG BASE_IMAGE

# --- build: clone the pinned source, apply the patch, test, build ------------
# Runs on the build host's native platform and cross-compiles (CGO_ENABLED=0),
# so the tests execute natively rather than under emulation.
FROM --platform=$BUILDPLATFORM ${GOLANG_IMAGE} AS build
ARG DISTRIBUTION_REPO
ARG DISTRIBUTION_SHA
ARG DISTRIBUTION_DESCRIBE
ARG PATCH_ID
ARG PATCH_REVISION
ARG TARGETOS
ARG TARGETARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Same environment Harbor's make/photon/registry/Dockerfile.binary uses:
# GOPATH-mode build (release/2.8 has no go.mod) with the vendored deps.
ENV DISTRIBUTION_DIR=/go/src/github.com/docker/distribution
ENV BUILDTAGS="include_oss include_gcs"
ENV GO111MODULE=auto
WORKDIR /go/src/github.com/docker/distribution

RUN set -eu; \
    for v in DISTRIBUTION_REPO DISTRIBUTION_SHA DISTRIBUTION_DESCRIBE PATCH_ID PATCH_REVISION TARGETOS TARGETARCH; do \
      eval "val=\${$v:-}"; [ -n "$val" ] || { echo "build arg $v is required (use build.sh)" >&2; exit 1; }; \
    done; \
    git init -q .; \
    git remote add origin "$DISTRIBUTION_REPO"; \
    git fetch -q --filter=blob:none --tags origin "$DISTRIBUTION_SHA"; \
    git checkout -q --detach FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "$DISTRIBUTION_SHA"; \
    describe="$(git describe --match 'v[0-9]*' --always)"; \
    [ "$describe" = "$DISTRIBUTION_DESCRIBE" ] || { echo "git describe $describe != $DISTRIBUTION_DESCRIBE" >&2; exit 1; }

COPY patches/ /patches/
RUN set -eu; \
    ls /patches/*.patch >/dev/null; \
    git apply --index /patches/*.patch; \
    git diff --cached --stat

# Targeted tests: every package the patch touches. `go test` runs with
# -vet=off and vet runs separately with -printf=false because go1.24's printf
# check rejects pre-existing, untouched test code in these packages
# (registry/storage/purgeuploads_test.go, registry/handlers/api_test.go).
# The race run needs cgo, so it is the only step with CGO_ENABLED=1.
RUN go vet -printf=false ./configuration/ ./registry/storage/ ./registry/handlers/ \
 && CGO_ENABLED=0 go test -vet=off -count=1 ./configuration/ ./registry/storage/ ./registry/handlers/ \
 && CGO_ENABLED=1 go test -vet=off -count=1 -race \
      -run 'TagLookup|TagStore|DeleteManifest|NewAppTagConcurrencyLimit' \
      ./registry/storage/ ./registry/handlers/

# Same make invocation as Harbor's Dockerfile.binary (`make PREFIX=/go clean
# binaries`, CGO_ENABLED=0, BUILDTAGS above). VERSION/REVISION are overridden so
# the binary identifies the patch: the git tree is dirty after `git apply`, and
# the Makefile's own `git describe --dirty` would only say ".m".
RUN set -eu; \
    patch_sum="$(cat /patches/*.patch | sha256sum | cut -d' ' -f1)"; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" make PREFIX=/go \
      VERSION="${DISTRIBUTION_DESCRIBE}+blockcast-${PATCH_ID}.${PATCH_REVISION}" \
      REVISION="${DISTRIBUTION_SHA}+patch.sha256.${patch_sum}" \
      clean binaries; \
    go version -m bin/registry

# --- base-perm: record the owner/mode of the binary being replaced ------------
FROM ${BASE_IMAGE} AS base-perm
RUN stat -c '%u:%g %a' /usr/bin/registry_DO_NOT_USE_GC > /tmp/base-perm

# --- final: the stock image with only the registry binary swapped -------------
FROM ${BASE_IMAGE}
ARG DISTRIBUTION_DESCRIBE
ARG PATCH_ID
ARG PATCH_REVISION
# harbor:harbor and 0755 are what Harbor's own make/photon/registry/Dockerfile
# leaves on this file; the RUN below fails the build if the base image disagrees.
COPY --from=build --chown=harbor:harbor --chmod=0755 \
     /go/src/github.com/docker/distribution/bin/registry /usr/bin/registry_DO_NOT_USE_GC
RUN --mount=type=bind,from=base-perm,source=/tmp/base-perm,target=/tmp/base-perm \
    set -eu; \
    want_perm="$(cat /tmp/base-perm)"; \
    got_perm="$(stat -c '%u:%g %a' /usr/bin/registry_DO_NOT_USE_GC)"; \
    [ "$got_perm" = "$want_perm" ] || { echo "owner/mode $got_perm != base $want_perm" >&2; exit 1; }; \
    want_ver="/usr/bin/registry_DO_NOT_USE_GC github.com/docker/distribution ${DISTRIBUTION_DESCRIBE}+blockcast-${PATCH_ID}.${PATCH_REVISION}"; \
    got_ver="$(/usr/bin/registry_DO_NOT_USE_GC --version)"; \
    [ "$got_ver" = "$want_ver" ] || { echo "version '$got_ver' != '$want_ver'" >&2; exit 1; }; \
    echo "verified: $got_ver ($got_perm)"
