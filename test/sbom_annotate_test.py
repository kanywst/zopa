#!/usr/bin/env python3
"""Contract for tools/sbom-annotate.sh.

That script decides whether a release ships. Inline in a workflow `run:`
block nothing could exercise it short of pushing a tag, which is the
most expensive place to find a broken jq filter -- so it lives in a file
and this pins what it promises: both CycloneDX `tools` shapes, the
annotations it adds, and each condition it refuses on.

    python3 test/sbom_annotate_test.py
"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "tools" / "sbom-annotate.sh"

ARTIFACT_BYTES = b"\x00asm\x01\x00\x00\x00"
# sha256 of ARTIFACT_BYTES, computed in setUp rather than hardcoded.
import hashlib

ARTIFACT_SHA = hashlib.sha256(ARTIFACT_BYTES).hexdigest()

TOOLS_OBJECT = {"components": [{"type": "application", "name": "syft", "version": "1.51.1"}]}
TOOLS_ARRAY = [{"vendor": "anchore", "name": "syft", "version": "1.0.0"}]


def sbom(tools, components=None):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"tools": tools},
        "components": components if components is not None else [],
    }


class Annotate(unittest.TestCase):
    def run_script(self, doc, *, artifact=ARTIFACT_BYTES, sha=ARTIFACT_SHA, licence="Apache License 2.0"):
        with TemporaryDirectory() as d:
            work = Path(d)
            (work / "sbom.json").write_text(json.dumps(doc))
            (work / "zopa.wasm").write_bytes(artifact)
            (work / "LICENSE").write_text(licence)
            proc = subprocess.run(
                [str(SCRIPT), "sbom.json", "zopa.wasm", sha, "v9.9.9", "LICENSE"],
                cwd=work, capture_output=True, text=True, check=False,
            )
            out = None
            if proc.returncode == 0:
                out = json.loads((work / "sbom.json").read_text())
            return proc, out

    def test_annotates_the_modern_tools_shape(self):
        proc, out = self.run_script(sbom(TOOLS_OBJECT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        c = out["metadata"]["component"]
        self.assertEqual(c["name"], "zopa")
        self.assertEqual(c["version"], "v9.9.9")
        self.assertEqual(c["licenses"][0]["license"]["id"], "Apache-2.0")
        self.assertEqual(c["hashes"][0]["content"], ARTIFACT_SHA)
        names = [t["name"] for t in out["metadata"]["tools"]["components"]]
        self.assertIn("syft", names)
        self.assertIn("zig", names)

    def test_migrates_the_pre_1_5_tools_array(self):
        proc, out = self.run_script(sbom(TOOLS_ARRAY))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        tools = out["metadata"]["tools"]["components"]
        # Migrated entries need the `type` the component schema requires,
        # or the compatibility branch emits a document that fails
        # stricter validation while every other check passes.
        for t in tools:
            self.assertIn("type", t, f"migrated tool without a type: {t}")
        self.assertIn("zig", [t["name"] for t in tools])

    def test_refuses_when_the_artifact_does_not_match_the_recorded_hash(self):
        # The artifact on disk differs from the sha handed in: the case a
        # guard comparing an argument to itself could never catch.
        proc, _ = self.run_script(sbom(TOOLS_OBJECT), artifact=b"different bytes")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("hashes to", proc.stderr)

    def test_refuses_a_scan_that_found_dependencies(self):
        # Zero is the answer for this repo; anything else means the scan
        # target drifted and syft walked the checkout root.
        noisy = sbom(TOOLS_OBJECT, components=[{"type": "library", "name": "some-action", "version": "v1"}])
        proc, _ = self.run_script(noisy)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("expected zero dependency components", proc.stderr)
        self.assertIn("some-action", proc.stderr)

    def test_refuses_when_the_licence_file_disagrees(self):
        proc, _ = self.run_script(sbom(TOOLS_OBJECT), licence="The MIT License")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("does not look like Apache 2.0", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
