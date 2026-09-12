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

    def test_negative_array_index_is_refused(self):
        self.assertRefused("allow if input.xs[-1] == 1", "whole non-negative number")

    def test_oversized_array_index_is_described_here_not_downstream(self):
        # Python ints are unbounded; ast.zig caps at 2**32-1. Without a
        # matching check the converter would emit a path the module
        # refuses as a bare InvalidPath, the one rejection in the walker
        # without a reason attached.
        self.assertRefused(
            "allow if input.xs[99999999999999999999] == 1", "above the maximum zopa accepts",
        )

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

    def test_largest_accepted_array_index_still_converts(self):
        # The ceiling itself converts, so the refusal beside it is a
        # bound rather than an off-by-one swallowing valid indices.
        ast = self.assertConverts("allow if input.xs[4294967295] == 1")
        self.assertEqual(ast["rules"][0]["body"][0]["left"]["path"][-1], 4294967295)

    def test_nullary_function_is_indistinguishable_and_converts(self):
        """Records a limitation, not a desired behaviour.

        OPA emits byte-identical heads for `f() if ...` and `f if ...`
        -- no `args` on either -- so the guard on function definitions
        cannot see the nullary case. It converts into a rule named `f`,
        addressable as data where OPA's function is not. This test
        exists so that the day OPA distinguishes them, it fails and
        someone decides deliberately.
        """
        nullary = self.assertConverts("f() if input.x == 1")
        plain = self.assertConverts("f if input.x == 1")
        self.assertEqual(nullary, plain)

    def test_array_index_becomes_a_numeric_segment(self):
        ast = self.assertConverts('allow if input.groups[1].name == "ops"')
        path = ast["rules"][0]["body"][0]["left"]["path"]
        self.assertEqual(path, ["input", "groups", 1, "name"])
        # A number, not the string that spells it -- the distinction the
        # evaluator relies on to keep an object from standing in for an
        # array.
        self.assertIsInstance(path[2], int)
        self.assertNotIsInstance(path[2], bool)

    def test_every_with_a_single_expression_body(self):
        ast = self.assertConverts("allow if every x in input.xs { x == 1 }")
        self.assertEqual(ast["rules"][0]["body"][0]["type"], "every")


if __name__ == "__main__":
    unittest.main(verbosity=2)
