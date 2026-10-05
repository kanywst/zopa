# Multi-stage Dockerfile for the zopa OCI image.
#
# Stage `build` compiles the wasm artifact with Zig 0.17.0 in
# `--release=small` mode. The final stage is a distroless `static`
# image so the only mutable bytes in the layer are the wasm itself.
#
# Layout in the final image:
#   /zopa.wasm                  -- the proxy-wasm module
#   /LICENSE, /NOTICE           -- Apache 2.0 requires both to travel
#                                  with the Work; the image redistributes
#                                  it on its own, outside this repo.
#
# Future PRs add /usr/local/bin/zopa-eval (CLI evaluator) and a
# vendored wasmtime binary; intentionally out of scope for v1 to
# keep the image as small as possible.

# syntax=docker/dockerfile:1.7

FROM docker.io/library/alpine:3.21 AS build
RUN apk add --no-cache curl tar xz minisign
# The compiler that builds the release artifact is verified before it
# runs: a tampered toolchain could drop fail-closed checks without any
# source diff showing it. Zig signs every release tarball with this
# minisign key (published at https://ziglang.org/download/), which is
# what setup-zig verifies in CI too.
ARG ZIG_VERSION=0.17.0
ARG ZIG_PUBKEY=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
WORKDIR /zig
RUN ARCH=$(uname -m) \
 && case "$ARCH" in \
        x86_64)  ZIG_ARCH=x86_64 ;; \
        aarch64) ZIG_ARCH=aarch64 ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && tarball="zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
 && curl -fsSLO "https://ziglang.org/download/${ZIG_VERSION}/${tarball}" \
 && curl -fsSLO "https://ziglang.org/download/${ZIG_VERSION}/${tarball}.minisig" \
 && minisign -Vm "$tarball" -P "$ZIG_PUBKEY" \
 && tar -xJf "$tarball" \
 && mv "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /opt/zig \
 && rm "$tarball" "$tarball.minisig"
ENV PATH="/opt/zig:$PATH"

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src
RUN zig build --release=small

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/zig-out/bin/zopa.wasm /zopa.wasm
COPY LICENSE NOTICE /
USER nonroot
LABEL org.opencontainers.image.source="https://github.com/kanywst/zopa"
LABEL org.opencontainers.image.description="zopa: proxy-wasm authorization engine"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL tech.zopa.proxy-wasm-version="0.2.1"
