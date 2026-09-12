#!/usr/bin/env bash
#
# Annotate a syft-generated CycloneDX SBOM with what syft cannot know,
# then refuse to pass on a document that does not describe the artifact.
#
# Extracted from .github/workflows/release.yml so it can be tested: this
# script decides whether a release ships, and inline in a `run:` block
# nothing could exercise it short of pushing a tag, which is the most
# expensive place to discover a broken jq filter.
#
#   tools/sbom-annotate.sh <sbom.json> <artifact> <sha256> <version> [licence-file]
#
# Rewrites <sbom.json> in place.

set -euo pipefail

sbom=${1:?sbom path}
artifact=${2:?artifact path}
sha=${3:?artifact sha256}
version=${4:?version}
licence_file=${5:-LICENSE}

zig_version=$(zig version)

tmp=$(mktemp)
jq --arg zig "$zig_version" \
   --arg sha "$sha" \
   --arg ver "$version" '
  # CycloneDX moved metadata.tools from an array of tool objects to an
  # object with a components list. Accept either so a syft upgrade
  # cannot silently break this. Pre-1.5 entries are bare
  # vendor/name/version with no `type`, which the component schema
  # requires -- backfill it, or the compatibility branch would emit a
  # document that fails stricter validation while every check here
  # still passed.
  (.metadata.tools) |= (
    if type == "array"
    then {"components": [.[] | {type: "application"} + .]}
    else . end
  )
  | .metadata.tools.components += [{
      "type": "application", "name": "zig", "version": $zig
    }]
  | .metadata.component = {
      "type": "library",
      "name": "zopa",
      "version": $ver,
      "description": "Authorization engine for proxy-wasm, compiled to wasm32-freestanding",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "hashes": [{"alg": "SHA-256", "content": $sha}],
      "externalReferences": [{"type": "vcs", "url": "https://github.com/kanywst/zopa"}]
    }' "$sbom" > "$tmp"
mv "$tmp" "$sbom"

# The hash is recomputed from the artifact on disk rather than reusing
# the value passed in: comparing an argument to itself would pass even
# if the artifact had been replaced after the SBOM was written, which is
# the only scenario worth guarding.
actual=$(shasum -a 256 "$artifact" | awk '{print $1}')
recorded=$(jq -r '.metadata.component.hashes[] | select(.alg == "SHA-256") | .content' "$sbom")
if [ "$actual" != "$recorded" ]; then
    echo "sbom records $recorded but $artifact hashes to $actual" >&2
    exit 1
fi

jq -e '.metadata.tools.components[] | select(.name == "zig")' "$sbom" >/dev/null

# Assert the scan scope, not just the bytes. The hash check proves the
# SBOM names the right artifact; it says nothing about what was scanned
# to produce it. If the scan target ever drifts -- an input rename in a
# future sbom-action, an accidental default to the workspace -- syft
# falls back to the checkout root and reports the ~60 Actions and
# .zig-cache false positives this exists to avoid, and every other check
# here would still pass.
#
# build.zig.zon declares no dependencies and the module is stdlib-only,
# so zero is the answer. Non-zero means the scan is wrong, not that a
# dependency appeared.
components=$(jq '.components | length' "$sbom")
if [ "$components" != "0" ]; then
    echo "expected zero dependency components (build.zig.zon declares none); got $components." >&2
    echo "the scan target is probably wrong -- check the sbom-action inputs." >&2
    jq -r '.components[] | "  \(.name) \(.version // "")"' "$sbom" >&2
    exit 1
fi

# Checked against the licence file rather than trusted from the jq
# above: a literal alone would keep claiming Apache-2.0 in a signed
# document after a licence change.
declared=$(jq -r '.metadata.component.licenses[0].license.id' "$sbom")
if ! grep -q "Apache License" "$licence_file" || [ "$declared" != "Apache-2.0" ]; then
    echo "sbom declares $declared but $licence_file does not look like Apache 2.0" >&2
    exit 1
fi

echo "sbom: $(jq -r '.specVersion' "$sbom"), $components dependency component(s), $declared"
