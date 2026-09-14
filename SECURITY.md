# Security Policy

## Supported versions

zopa is pre-1.0. Only the latest tag receives security fixes.

## Reporting a vulnerability

Do not open a public GitHub issue.

Use [GitHub's private vulnerability reporting][advisory] on this repository. A maintainer will acknowledge within 72 hours and coordinate a fix.

If private reporting is unavailable, email the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md) with `[zopa security]` in the subject.

[advisory]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

## Scope

In scope:

- Memory safety issues in the wasm module (out-of-bounds reads/writes, use-after-free, leaks across the request arena).
- Logic bugs that cause `evaluate()` to return `allow` when the policy forbids the request.
- **Any path that fails open.** zopa's posture is that every situation it cannot decide -- unreadable input, a policy that will not build, a host call that errors, a request body it could only see part of -- results in a deny. A path that reaches `allow`, or that lets a request through unevaluated, is a vulnerability even if nothing crashes.
- **Parser differentials.** zopa reads the same bytes as the service behind it. An input that zopa and a mainstream JSON parser (Go, JavaScript, OPA) read differently is a way to make a policy match one value while the backend acts on another. Number grammar, duplicate keys, escapes, and encoding all count.
- proxy-wasm ABI misuse that crashes the host or escapes the wasm sandbox.
- Parser bugs that cause unbounded recursion, stack overflow, or memory blowup on adversarial input. Note that `usize` is 32 bits on wasm32, so arithmetic over host-supplied length fields can wrap.

Out of scope:

- Denial of service from oversized policies or inputs that fit within configured limits. zopa enforces a recursion cap; configure your proxy to bound request size.
- Issues in dependencies of the test harness (Node, wasmtime, Envoy). Report those upstream.

## Disclosure

Fixes are released as soon as a patch is verified. A GitHub Security Advisory is published with the fix release.

## Verifying a release

Every tagged release attaches, for `zopa-<tag>.wasm`:

| Asset | What it is |
| --------------------------------- | ------------------------------------------------------------ |
| `.sha256` | Checksum of the wasm. |
| `.sigstore.json` | Keyless cosign bundle over the wasm. |
| `.intoto.jsonl` | SLSA v1.0 build provenance, generated in an isolated builder. |
| `.cdx.json` | CycloneDX SBOM: the artifact's hash, licence and toolchain. |
| `.cdx.json.sigstore.json` | Keyless cosign bundle over the SBOM. |

```bash
tag=v0.5.0
base="https://github.com/kanywst/zopa/releases/download/$tag"
curl -fsSLO \
  "$base/zopa-$tag.wasm" \
  -O "$base/zopa-$tag.wasm.sha256" \
  -O "$base/zopa-$tag.wasm.sigstore.json" \
  -O "$base/zopa-$tag.wasm.cdx.json" \
  -O "$base/zopa-$tag.wasm.cdx.json.sigstore.json"

# 1. the artifact matches its checksum
shasum -a 256 -c "zopa-$tag.wasm.sha256"

# 2. the artifact was signed by this repository's *release* workflow.
#    Pin the workflow path, not just the repository: a repo-wide regexp
#    would also accept a signature minted by any other workflow here,
#    which is a much weaker statement than it looks.
identity="https://github.com/kanywst/zopa/.github/workflows/release.yml@refs/tags/$tag"
verify() {
  cosign verify-blob \
    --bundle "$1.sigstore.json" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$1"
}
verify "zopa-$tag.wasm"

# 3. the SBOM was signed by the same workflow -- an unsigned SBOM can be
#    swapped for one claiming anything, so verifying the wasm alone is
#    not enough if you intend to trust the SBOM
verify "zopa-$tag.wasm.cdx.json"

# 4. the SBOM describes the artifact you just verified, not some other
#    build
test "$(jq -r '.metadata.component.hashes[] | select(.alg == "SHA-256") | .content' \
          "zopa-$tag.wasm.cdx.json")" \
   = "$(awk '{print $1}' "zopa-$tag.wasm.sha256")" \
  && echo "sbom matches the artifact"
```

Steps 3 and 4 are the ones people skip. A signed artifact beside an SBOM you have not checked tells you nothing about the SBOM.

The fifth asset, `.intoto.jsonl`, is SLSA v1.0 build provenance and is verified with a different tool -- `cosign verify-blob` does not read it. It states which workflow, at which commit, produced the artifact:

```bash
slsa-verifier verify-artifact "zopa-$tag.wasm" \
  --provenance-path "zopa-$tag.wasm.intoto.jsonl" \
  --source-uri github.com/kanywst/zopa \
  --source-tag "$tag"
```

The signature says the release workflow signed these bytes; the provenance says what built them. They answer different questions and neither substitutes for the other.

The SBOM reports **zero dependency components**, and that is the accurate answer rather than an empty document: `build.zig.zon` declares no dependencies and the module is Zig stdlib only. It is generated by scanning the built artifact rather than the source tree -- a `dir:.` scan of this repository reports the GitHub Actions pinned in the workflows and several false positives read out of `.zig-cache`, none of which the wasm depends on. It is signed for the same reason the wasm is: an unsigned SBOM can be swapped for one that claims anything.
