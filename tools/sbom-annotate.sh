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

# Establish that this is syft's own output before annotating it. This is
# the check that catches a scan which broke rather than one that found
# nothing -- see the components check below for why the two cannot be
# told apart by looking for a `components` key.
#
# bomFormat/specVersion prove the file is a CycloneDX document and not a
# truncated write or an error payload; the syft entry in metadata.tools
# proves syft is what produced it. metadata.tools is normalised by the jq
# below, so this has to read the pre-annotation shape -- either of them.
if ! jq -e '.bomFormat == "CycloneDX" and (.specVersion | type == "string" and length > 0)' \
     "$sbom" >/dev/null; then
    echo "$sbom is not a CycloneDX document; the scan did not produce a usable file" >&2
    exit 1
fi
if ! jq -e '[(.metadata.tools | if type == "array" then .[] else .components[] end).name]
            | index("syft")' "$sbom" >/dev/null 2>&1; then
    echo "$sbom does not name syft in metadata.tools; it is not a syft scan result" >&2
    exit 1
fi

# A `components` key that is neither absent, null, nor an array means
# something rewrote the document into a shape this script cannot reason
# about. Zero components is legitimate (below); a string or an object
# there is not.
if ! jq -e '(.components == null) or (.components | type == "array")' "$sbom" >/dev/null; then
    echo "$sbom has a components key that is not an array" >&2
    exit 1
fi

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
#
# Absent is zero, and that is not laxity: syft omits `components`
# entirely when it finds nothing, which for this repo is every release.
# v0.5.0 failed here because an earlier version of this check required
# the key to be present, and so rejected the one shape a correct scan of
# a zero-dependency artifact can produce. "Key missing" therefore cannot
# mean "the scan broke" -- what distinguishes a broken scan is that it
# does not produce syft's document envelope at all, which is checked
# above, before the annotation.
components=$(jq '(.components // []) | length' "$sbom")
if [ "$components" != "0" ]; then
    echo "expected zero dependency components (build.zig.zon declares none); got $components." >&2
    echo "the scan target is probably wrong -- check the sbom-action inputs." >&2
    jq -r '.components[] | "  \(.name) \(.version // "")"' "$sbom" >&2
    exit 1
fi

# The SBOM's licence id is set by the jq above, so reading it back and
# comparing it to the same literal proves nothing -- it is true by
# construction. What has to be checked is the file it claims to
# describe, and a substring match on "Apache License" would accept
# "Apache License, Version 1.1" just as happily.
#
# So: the digest of the canonical Apache License 2.0. LICENSE was
# restored to it byte-for-byte in v0.4.1 after three years of shipping a
# paraphrase, and this keeps that true -- an edited LICENSE fails the
# release rather than being described as Apache-2.0 in a signed
# document.
canonical_apache_2_0=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
licence_sha=$(shasum -a 256 "$licence_file" | awk '{print $1}')
declared=$(jq -r '.metadata.component.licenses[0].license.id' "$sbom")
if [ "$licence_sha" != "$canonical_apache_2_0" ]; then
    echo "$licence_file is not the canonical Apache License 2.0" >&2
    echo "  expected sha256 $canonical_apache_2_0" >&2
    echo "  got             $licence_sha" >&2
    echo "the sbom would declare $declared for a file that is not it." >&2
    exit 1
fi

echo "sbom: $(jq -r '.specVersion' "$sbom"), $components dependency component(s), $declared"
