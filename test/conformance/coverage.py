#!/usr/bin/env python3
"""Report which Rego constructs `tools/rego2ast.py` can convert.

The README says zopa's AST "covers a useful subset of Rego" without
saying which subset, and the conformance suite answers only for the ten
policies someone thought to write down. This walks a corpus of small,
single-construct policies instead, so the answer is a table rather than
an adjective -- and so a construct that starts converting, or stops,
shows up as a diff rather than as nobody noticing.

It asserts nothing about correctness: converting is not the same as
evaluating correctly, which is what test/conformance/run.py is for.
This measures reach.

    python3 test/conformance/coverage.py            # table
    python3 test/conformance/coverage.py --json     # machine-readable
    python3 test/conformance/coverage.py --check FILE
        # fail if reach has changed against a recorded baseline
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
REGO2AST = REPO / "tools" / "rego2ast.py"

# One construct per entry, kept to the smallest policy that exercises it.
# `group` is only for reading the table; nothing branches on it.
CORPUS: list[tuple[str, str, str]] = [
    # --- rule shapes ---
    ("rule/constant", "constant value", "default allow = true"),
    ("rule/default-deny", "default plus a body", "default allow = false\nallow if input.x == 1"),
    ("rule/multi-definition", "two definitions of one rule", "allow if input.a == 1\nallow if input.b == 2"),
    ("rule/named", "a rule that is not `allow`", "allow_body if input.x == 1"),
    ("rule/value-expr", "rule with an explicit value", "allow = true if input.x == 1"),

    # --- comparison ---
    ("cmp/eq", "equality", "allow if input.x == 1"),
    ("cmp/neq", "inequality", "allow if input.x != 1"),
    ("cmp/lt", "less than", "allow if input.x < 1"),
    ("cmp/lte", "less or equal", "allow if input.x <= 1"),
    ("cmp/gt", "greater than", "allow if input.x > 1"),
    ("cmp/gte", "greater or equal", "allow if input.x >= 1"),
    ("cmp/assign", "assignment in a body", "allow if {\n\tx := input.x\n\tx == 1\n}"),

    # --- literals ---
    ("lit/string", "string literal", 'allow if input.x == "s"'),
    ("lit/number", "number literal", "allow if input.x == 1"),
    ("lit/float", "float literal", "allow if input.x == 1.5"),
    ("lit/bool", "boolean literal", "allow if input.x == true"),
    ("lit/null", "null literal", "allow if input.x == null"),
    ("lit/array", "array literal", 'allow if input.x == ["a", "b"]'),
    ("lit/object", "object literal", 'allow if input.x == {"k": "v"}'),
    ("lit/set", "set literal", 'allow if input.x == {"a", "b"}'),

    # --- refs ---
    ("ref/input-field", "input field", "allow if input.x == 1"),
    ("ref/nested", "nested input path", "allow if input.a.b.c == 1"),
    ("ref/bracket", "bracket string key", 'allow if input["a"] == 1'),
    ("ref/array-index", "array index", "allow if input.x[0] == 1"),
    ("ref/array-index-nested", "array index followed by a field", 'allow if input.g[1].name == "ops"'),
    ("ref/data", "data document", "allow if data.x == 1"),

    # --- logic ---
    ("logic/and", "implicit conjunction", "allow if {\n\tinput.a == 1\n\tinput.b == 2\n}"),
    ("logic/not", "negation", "allow if not input.banned"),
    ("logic/truthy", "bare truthy reference", "allow if input.flag"),

    # --- iteration ---
    ("iter/some-in", "some ... in", "allow if {\n\tsome x in input.xs\n\tx == 1\n}"),
    ("iter/every-in", "every ... in", "allow if every x in input.xs { x == 1 }"),
    ("iter/every-multi", "every with a multi-expression body",
     "allow if every x in input.xs {\n\tx != 0\n\tx < 10\n}"),
    ("iter/underscore", "wildcard iteration", "allow if input.xs[_] == 1"),

    # --- builtins ---
    ("builtin/startswith", "startswith", 'allow if startswith(input.p, "/a")'),
    ("builtin/endswith", "endswith", 'allow if endswith(input.p, ".x")'),
    ("builtin/contains", "contains", 'allow if contains(input.p, "a")'),
    ("builtin/count", "count", "allow if count(input.xs) == 1"),
    ("builtin/sprintf", "sprintf", 'allow if sprintf("%v", [input.x]) == "1"'),
    ("builtin/lower", "lower", 'allow if lower(input.p) == "a"'),
    ("builtin/split", "split", 'allow if count(split(input.p, "/")) == 2'),
    ("builtin/in-operator", "the `in` membership operator", "allow if input.x in input.xs"),

    # --- comprehensions and functions ---
    ("comp/array", "array comprehension", "allow if count([x | some x in input.xs]) == 1"),
    ("comp/set", "set comprehension", "allow if count({x | some x in input.xs}) == 1"),
    ("func/user-defined", "user-defined function",
     "allow if f(input.x)\n\nf(x) if x == 1"),
    ("func/definition-only", "function definition on its own", "f(x) if x == 1"),
    ("rule/else", "`else` fallback branch", "allow if input.x == 1 else = false if input.y == 2"),
    ("misc/with", "the `with` modifier", "allow if input.x == 1 with input.y as 2"),
    ("misc/partial-set", "partial set rule", 'deny contains "x" if input.x == 1'),
    ("misc/partial-object", "partial object rule", "p[input.x] = input.y if input.x == 1"),
]


# rego2ast exits 3 for a construct it knows it cannot express. Anything
# else non-zero is the converter falling over -- a traceback where the
# caller expects a decision -- and the two must not look the same here.
# Both would otherwise register as "does not convert", so a clean bail
# decaying into a crash (which is what the standalone `some ... in`
# handling was before this corpus existed) would leave the table
# unchanged and go unnoticed.
UNSUPPORTED_EXIT = 3


def convert(rego: str) -> tuple[bool, str]:
    """Run `opa parse | rego2ast` over one policy.

    Returns (ok, detail). `detail` is prefixed with `CRASH:` when the
    converter failed in a way it does not claim to handle.
    """
    source = f"package authz\n\n{rego}\n"
    try:
        parsed = subprocess.run(
            ["opa", "parse", "/dev/stdin", "--format", "json"],
            input=source, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        sys.exit("coverage: no `opa` on PATH")
    if parsed.returncode != 0:
        # The policy does not compile at all. That is a corpus bug --
        # a typo in a row, or an `opa` grammar change under us -- not a
        # converter gap, and recording it as "does not convert" would
        # quietly shrink the reach number the README cites. Marked like
        # a crash so it fails the run rather than resting in the table.
        first = (parsed.stderr or "").strip().splitlines()
        return False, f"CRASH: rego did not parse: {first[0] if first else '?'}"

    converted = subprocess.run(
        [sys.executable, str(REGO2AST)],
        input=parsed.stdout, capture_output=True, text=True, check=False,
    )
    if converted.returncode == 0:
        return True, ""
    detail = (converted.stderr or converted.stdout or "").strip().splitlines()
    last = detail[-1] if detail else "unknown failure"
    if converted.returncode != UNSUPPORTED_EXIT:
        return False, f"CRASH: exit {converted.returncode}: {last}"
    return False, last


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    ap.add_argument("--check", metavar="FILE", help="compare against a recorded baseline and fail on any change")
    args = ap.parse_args()

    results = {}
    details = {}
    for key, label, rego in CORPUS:
        ok, detail = convert(rego)
        results[key] = ok
        details[key] = (label, detail)

    supported = sum(1 for v in results.values() if v)
    # Both a converter traceback and a corpus policy that will not
    # compile: neither is a real answer about reach.
    crashes = sorted(k for k, (_, d) in details.items() if d.startswith("CRASH:"))

    if args.json:
        print(json.dumps({"supported": supported, "total": len(results), "constructs": results}, indent=2))
    else:
        width = max(len(k) for k in results)
        print(f"{'construct'.ljust(width)}  reach  detail")
        print(f"{'-' * width}  -----  ------")
        for key, (label, detail) in details.items():
            mark = "yes" if results[key] else "NO "
            note = label if results[key] else f"{label} -- {detail}"
            print(f"{key.ljust(width)}  {mark}    {note}")
        print(f"\n{supported}/{len(results)} constructs convert")
        print("Converting is not the same as evaluating correctly; see test/conformance/run.py for that.")

    # A crash is never an acceptable resting state, whatever the
    # baseline says: rego2ast promises either an AST or a described
    # refusal, and a traceback is neither.
    if crashes:
        for key in crashes:
            print(f"\nCRASH  {key}: {details[key][1]}", file=sys.stderr)
        print(
            "\nEvery row must be a real answer: rego2ast returns an AST or a described\n"
            "refusal, and every corpus policy must compile. Neither is a reach result.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        baseline = json.loads(Path(args.check).read_text())["constructs"]
        gained = sorted(k for k, v in results.items() if v and not baseline.get(k, False))
        lost = sorted(k for k, v in results.items() if not v and baseline.get(k, False))
        unknown = sorted(set(results) - set(baseline))
        dropped = sorted(set(baseline) - set(results))
        if not (gained or lost or unknown or dropped):
            print(f"\ncoverage unchanged against {args.check}")
            return 0
        # Gaining reach is good news, but it still has to be recorded --
        # otherwise the committed table drifts from the truth silently,
        # which is the whole thing this file exists to prevent.
        for k in lost:
            print(f"\nLOST     {k}: converted before, does not now", file=sys.stderr)
        for k in gained:
            print(f"GAINED   {k}: converts now, did not before", file=sys.stderr)
        for k in unknown:
            print(f"NEW      {k}: not in the baseline", file=sys.stderr)
        for k in dropped:
            print(f"REMOVED  {k}: in the baseline, not in the corpus", file=sys.stderr)
        print(
            "\nRe-record if intended:\n"
            "  python3 test/conformance/coverage.py --json > test/conformance/coverage.json",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
