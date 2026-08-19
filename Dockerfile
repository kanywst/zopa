# Multi-stage Dockerfile for the zopa OCI image.
#
# Stage `build` compiles the wasm artifact with Zig 0.16.0 in
# `--release=small` mode. The final stage is a distroless `static`
# image so the only mutable bytes in the layer are the wasm itself.
#
# Layout in the final image:
#   /zopa.wasm                  -- the proxy-wasm module
#
# Future PRs add /usr/local/bin/zopa-eval (CLI evaluator) and a
# vendored wasmtime binary; intentionally out of scope for v1 to
# keep the image as small as possible.

# syntax=docker/dockerfile:1.7

FROM docker.io/library/alpine:3.21 AS build
RUN apk add --no-cache curl tar xz
WORKDIR /zig
RUN ARCH=$(uname -m) \
 && case "$ARCH" in \
        x86_64)  ZIG_ARCH=x86_64 ;; \
        aarch64) ZIG_ARCH=aarch64 ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://ziglang.org/download/0.16.0/zig-${ZIG_ARCH}-linux-0.16.0.tar.xz" | tar -xJ \
 && mv "zig-${ZIG_ARCH}-linux-0.16.0" /opt/zig
ENV PATH="/opt/zig:$PATH"

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src
RUN zig build --release=small

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/zig-out/bin/zopa.wasm /zopa.wasm
USER nonroot
LABEL org.opencontainers.image.source="https://github.com/kanywst/zopa"
LABEL org.opencontainers.image.description="zopa: proxy-wasm authorization engine"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL tech.zopa.proxy-wasm-version="0.2.1"
