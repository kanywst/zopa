# Distroless OCI image

Status: Proposed (draft PR, design doc only).
Tracking: ROADMAP.md → Medium term ("Distroless OCI image").

## Motivation

Today the only release artifact is `zopa-<tag>.wasm` plus its SLSA
provenance and cosign signature. That works when the user already has
Envoy and just wants to drop in the wasm file. It doesn't help when:

- A platform team wants to pin "the wasm + a known-good runtime to
  test it against" as a single immutable reference.
- A CI pipeline needs to validate a policy AST without installing
  anything except `docker run`.
- A Kubernetes operator wants to mount the wasm into Envoy via an
  initContainer, which is much cleaner with an OCI image than with
  raw HTTP downloads.

A small, signed OCI image with the `.wasm` and a tiny CLI for ad-hoc
evaluation closes the gap.

## Goals

1. Multi-stage Dockerfile producing a `FROM scratch` (or distroless
   base) image:
   - `/zopa.wasm` at the path proxy-wasm hosts expect.
   - `/usr/local/bin/zopa-eval` (statically linked) that runs
     `evaluate(input.json, ast.json)` on stdin / argv.
   - `/usr/local/bin/wasmtime` (vendored at a pinned version) for
     hosts that want to confirm the wasm boots before mounting.
1. CI workflow `.github/workflows/oci.yml`:
   - Builds on `v*` tags and on `main`.
   - Pushes to `ghcr.io/kanywst/zopa:<tag>` and `:edge`.
   - Multi-arch: `linux/amd64`, `linux/arm64`.
   - Cosign keyless signing of the image manifest, attaching the same
     SLSA v1.0 provenance generator already used for the wasm.
1. Image metadata declares the wasm hash and the proxy-wasm ABI
   version via OCI labels (`org.opencontainers.image.*` plus
   `tech.zopa.proxy-wasm-version`).

## Non-goals

- Bundling Envoy or any runtime that proxies traffic. The image is a
  carrier for the wasm and a CLI evaluator, not a server.
- A Helm chart, operator, or CRD. The image is one ingredient; how to
  deploy is downstream.
- Supporting Windows containers. Out of scope.

## Design sketch

### Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.7
FROM ziglang/zig:0.16.0 AS build
WORKDIR /src
COPY . .
RUN zig build --release=small \
 && zig build cli   # produces zig-out/bin/zopa-eval (native target)

FROM cgr.dev/chainguard/wasmtime:latest AS wasmtime

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/zig-out/bin/zopa.wasm    /zopa.wasm
COPY --from=build /src/zig-out/bin/zopa-eval    /usr/local/bin/zopa-eval
COPY --from=wasmtime /usr/local/bin/wasmtime    /usr/local/bin/wasmtime
ENTRYPOINT ["/usr/local/bin/zopa-eval"]
LABEL org.opencontainers.image.source=https://github.com/kanywst/zopa
LABEL tech.zopa.proxy-wasm-version=0.2.1
```

Base candidates:

- `gcr.io/distroless/static-debian12:nonroot` (recommended; familiar,
  gets CVE feeds via Google).
- `cgr.dev/chainguard/static:latest` (smaller, signed by Chainguard).

Pick one in the implementation PR, document the rationale.

### `zopa-eval` CLI

A new build target in `build.zig` that targets the host architecture
and links a thin `main` around the same `evaluate` function the wasm
exports:

```bash
$ echo '{"user":{"role":"admin"}}' | \
    zopa-eval --ast policy.json
1
```

Exit codes mirror the wasm: `0` allow, `1` deny, `2` error. (The
inversion vs the wasm `i32` is intentional; CLI conventions use 0
for success.)

## API impact

- New release artifact: OCI image at `ghcr.io/kanywst/zopa`.
- New build target `zopa-eval` (CLI only, not part of the wasm).
- No change to the wasm exports.

## Test plan

- CI builds the image on every PR (no push), runs `docker run --rm
  ghcr.io/kanywst/zopa:edge --version` as a smoke test.
- A `tools/verify-image.sh` script that pulls the latest image,
  cosign-verifies it, and runs the smoke test. Used in release
  validation.
- Conformance harness (see `opa-conformance-harness.md`) gains an
  optional `--image` mode that runs zopa via the OCI image instead of
  the host build.

## Open questions

- Which distroless variant? Default is `static-debian12:nonroot`;
  Chainguard's `static` is smaller but adds an external dependency.
- Should `wasmtime` be vendored in the image at all? It nearly
  doubles the image size. Argument for: lets users confirm the wasm
  boots without installing anything. Argument against: the image
  is no longer minimal.
- Tag policy: `:edge` for `main`, `:vX.Y.Z` for tags, `:latest` aliases
  the highest semver. The aliasing is contentious; revisit on the
  first stable release.
