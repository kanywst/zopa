#!/usr/bin/env python3
"""Diagnostics `tools/rego2ast.py` promises, asserted rather than assumed.

The reach table in `coverage.py` records convert-or-not as a boolean, so
a refusal naming the wrong construct still shows as "does not convert".
That matters here: the set and object spellings of a partial rule take
different paths through the head check, the distinction is called out
in the changelog as worth reading twice, and nothing else pins that the
message gets it right.

    python3 test/conformance/rego2ast_test.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
REGO2AST = REPO / "tools" / "rego2ast.py"

UNSUPPORTED_EXIT = 3


def convert(rego: str) -> subprocess.CompletedProcess[str]:
    parsed = subprocess.run(
        ["opa", "parse", "/dev/stdin", "--format", "json"],
        input=f"package authz\n\n{rego}\n", capture_output=True, text=True, check=False,
    )
    if parsed.returncode != 0:
        raise AssertionError(f"test policy did not parse: {parsed.stderr.strip()}")
    return subprocess.run(
        [sys.executable, str(REGO2AST)],
        input=parsed.stdout, capture_output=True, text=True, check=False,
    )


class Refusals(unittest.TestCase):
    def assertRefused(self, rego: str, needle: str) -> None:
        result = convert(rego)
        self.assertEqual(
            result.returncode, UNSUPPORTED_EXIT,
            f"expected a clean refusal (exit {UNSUPPORTED_EXIT}), got {result.returncode}: "
            f"{result.stderr.strip()}",
        )
        detail = json.loads(result.stderr)["detail"]
        self.assertIn(needle, detail)

    def test_partial_set_is_named_a_set(self):
        self.assertRefused('deny contains "x" if input.x == 1', "partial set rule `deny`")

    def test_partial_object_is_named_an_object(self):
        # The spelling a guard testing for a missing value skips: this
        # head carries a key *and* a value.
        self.assertRefused("p[input.x] = input.y if input.x == 1", "partial object rule `p`")

    def test_with_modifier_says_why(self):
        self.assertRefused("allow if input.x == 1 with input.y as 2", "`with` modifier")

    def test_standalone_some_says_why(self):
        self.assertRefused(
            "allow if {\n\tsome x in input.xs\n\tx == 1\n}", "standalone `some ... in`",
        )

    def test_else_chain_says_the_branch_would_be_dropped(self):
        self.assertRefused(
            "allow if input.x == 1 else = false if input.y == 2", "`else` on rule `allow`",
        )

    def test_function_definition_is_refused(self):
        # The call site was already caught; the definition converted
        # into a rule whose parameter resolved against the input.
        self.assertRefused("f(x) if x == 1", "function definition `f`")

    def test_unnamed_operator_is_described(self):
        # `in` reaches OPA's AST as internal.member_2 and has no bare
        # name; reporting an empty one tells the reader nothing.
        self.assertRefused("allow if input.x in input.xs", "internal.member_2")


class Conversions(unittest.TestCase):
    """The shapes next door to a refusal, which must keep working."""

    def assertConverts(self, rego: str) -> dict:
        result = convert(rego)
        self.assertEqual(result.returncode, 0, result.stderr.strip())
        return json.loads(result.stdout)

    def test_complete_rule_with_a_non_boolean_value(self):
        # Has a value and no key: the neighbour of the partial-object
        # case, and the one a key-presence check must not catch.
        ast = self.assertConverts('allow = "yes" if input.x == 1')
        self.assertEqual(ast["rules"][0]["value"], {"type": "value", "value": "yes"})

    def test_default_rule(self):
        ast = self.assertConverts("default allow = false")
        self.assertTrue(ast["rules"][0]["default"])

    def test_every_with_a_single_expression_body(self):
        ast = self.assertConverts("allow if every x in input.xs { x == 1 }")
        self.assertEqual(ast["rules"][0]["body"][0]["type"], "every")


if __name__ == "__main__":
    unittest.main(verbosity=2)
