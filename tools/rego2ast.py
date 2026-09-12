#!/usr/bin/env python3
"""Convert `opa parse --format json` output into zopa-shaped AST JSON.

Reads OPA's parsed-AST JSON on stdin, writes zopa's AST JSON on stdout.

This is the v1 walker: it covers the subset of Rego that zopa's
evaluator supports. Anything outside that subset (user-defined
functions, `with` overrides, partial eval, set comprehensions, ...)
errors out with a descriptive message naming the unsupported node so
the caller can decide to skip the fixture or fail the run.

Usage:
    opa parse module.rego --format json | python3 tools/rego2ast.py

Standalone errors exit non-zero with a JSON `{"error": ...}` body on
stderr.
"""

from __future__ import annotations

import json
import sys
from typing import Any


class Unsupported(Exception):
    """Rego construct outside the v1 conformance subset."""


# ---------------------------------------------------------------------------
# Operator + builtin tables. Comparators map onto zopa's `compare` op
# names; builtins onto `call` names.
# ---------------------------------------------------------------------------

COMPARE_OPS = {"equal": "eq", "neq": "neq", "lt": "lt", "lte": "lte", "gt": "gt", "gte": "gte"}

BUILTINS = {"startswith", "endswith", "contains", "count"}


# ---------------------------------------------------------------------------
# Module / Rule walkers.
# ---------------------------------------------------------------------------


def walk_module(module: dict[str, Any]) -> dict[str, Any]:
    """Top-level entry. Returns a zopa `Module` JSON."""
    pkg_path = module.get("package", {}).get("path", [])
    # OPA encodes the package as `data.<a>.<b>...`; drop the leading `data`.
    pkg = ".".join(seg["value"] for seg in pkg_path[1:])

    rules = [walk_rule(r) for r in module.get("rules", [])]
    out: dict[str, Any] = {"type": "module", "rules": rules}
    if pkg:
        out["package"] = pkg
    return out


def walk_rule(rule: dict[str, Any]) -> dict[str, Any]:
    head = rule["head"]
    name = head["name"]

    # A partial rule builds a collection across every definition that
    # holds: `deny contains msg if ...` a set, `p[k] = v if ...` an
    # object. zopa rules are complete -- one name, one value -- so
    # either shape loses what it collected.
    #
    # The test is the presence of a key, not the absence of a value. A
    # partial *object* head carries both, so checking `value is None`
    # catches only the set spelling and lets `p[k] = v` through the
    # regular path below, where the key is never read and is silently
    # discarded -- the same "converts fine, means something else" bug
    # this guard exists to stop.
    if head.get("key") is not None:
        kind = "set" if head.get("value") is None else "object"
        raise Unsupported(
            f"partial {kind} rule `{name}` not supported: "
            "zopa rules are complete, so the collected values would be lost"
        )

    out: dict[str, Any] = {"type": "rule", "name": name}

    if rule.get("default"):
        out["default"] = True
        out["value"] = walk_term_as_value(head["value"])
        return out

    # Regular rule. Body is the list of expressions; head value (if
    # not the implicit `true`) becomes the rule's `value`.
    body = [walk_expr(e) for e in rule.get("body", [])]
    out["body"] = body

    head_val = head.get("value")
    if head_val is not None and not _is_literal_true(head_val):
        out["value"] = walk_term_as_value(head_val)

    return out


def _is_literal_true(term: dict[str, Any]) -> bool:
    return term.get("type") == "boolean" and term.get("value") is True


# ---------------------------------------------------------------------------
# Expression walker.
#
# An OPA `Expr` has either:
#   - terms: <Term>           single-term truthy check
#   - terms: [<Term>, ...]    call form (op_ref, arg1, arg2, ...)
#   - terms: {body, domain, key, value}    every / some-in iterator
#
# Plus an optional `negated: true` flag wrapping the whole thing in a
# logical NOT.
# ---------------------------------------------------------------------------


def walk_expr(expr: dict[str, Any]) -> dict[str, Any]:
    # `with` rewrites the document the body is evaluated against. zopa
    # has no equivalent, and dropping the modifier silently would emit
    # an AST that answers a different question than the Rego it came
    # from -- the same class of divergence the JSON parser is strict
    # about, arriving through the converter instead.
    if expr.get("with"):
        raise Unsupported("`with` modifier not supported: it would change the input the body sees")

    inner = walk_expr_inner(expr["terms"])
    if expr.get("negated"):
        return {"type": "not", "expr": inner}
    return inner


def walk_expr_inner(terms: Any) -> dict[str, Any]:
    if isinstance(terms, list):
        return walk_call_form(terms)

    if isinstance(terms, dict):
        if "domain" in terms:
            return walk_every(terms)
        # A bare `some x in xs` declares a binding for the expressions
        # that follow it in the same body. zopa's `some` is different:
        # it owns the body it binds over. Expressing one as the other
        # means restructuring the rule, which the converter does not do.
        # Without this the dict falls through to `walk_term`, which
        # reaches for a "type" key that a symbols declaration does not
        # have and dies with a KeyError -- a traceback where the runner
        # expects either an AST or a clean `Unsupported`.
        if "symbols" in terms:
            raise Unsupported(
                "standalone `some ... in` not supported: zopa's `some` binds over its own "
                "body, so the declaration cannot be lifted out of it"
            )
        # Single-term form. In body position, evaluate the term and
        # treat truthiness directly. zopa's evaluator handles this:
        # a bare `value` / `ref` resolves and is checked against
        # `false` / `nil`.
        return walk_term(terms)

    raise Unsupported(f"unrecognized terms shape: {type(terms).__name__}")


def walk_call_form(terms: list[dict[str, Any]]) -> dict[str, Any]:
    op_ref = terms[0]
    args = terms[1:]

    op_name = _flat_var_name(op_ref)
    if op_name in COMPARE_OPS:
        if len(args) != 2:
            raise Unsupported(f"comparator {op_name} expects 2 args, got {len(args)}")
        return {
            "type": "compare",
            "op": COMPARE_OPS[op_name],
            "left": walk_term(args[0]),
            "right": walk_term(args[1]),
        }

    if op_name in BUILTINS:
        return {
            "type": "call",
            "name": op_name,
            "args": [walk_term(a) for a in args],
        }

    raise Unsupported(f"unsupported call: {op_name or _describe_ref(op_ref)}")


def walk_every(terms: dict[str, Any]) -> dict[str, Any]:
    domain = walk_term(terms["domain"])
    body_exprs = [walk_expr(e) for e in terms.get("body", [])]
    body_inner = body_exprs[0] if len(body_exprs) == 1 else _and_chain(body_exprs)

    value = terms.get("value")
    if value is None or value.get("type") != "var":
        raise Unsupported("every: missing iteration variable name")

    out: dict[str, Any] = {
        "type": "every",
        "var": value["value"],
        "source": domain,
        "body": body_inner,
    }
    return out


def _and_chain(exprs: list[dict[str, Any]]) -> dict[str, Any]:
    # zopa has no native `and` node; bodies are implicit AND. Inside
    # an iterator, multiple body statements collapse into a synthetic
    # nested rule. v1: only support single-expression every bodies.
    raise Unsupported("multi-expression every body not supported in v1")


# ---------------------------------------------------------------------------
# Term walker.
#
# OPA terms are:
#   {type: boolean | number | string | null, value: ...}     literal
#   {type: ref, value: [<seg>, ...]}                          path ref
#   {type: var, value: "x"}                                   bare var
#   {type: array, value: [<term>, ...]}                       array literal
#   {type: call, value: [<ref>, <arg>, ...]}                  inline call
# ---------------------------------------------------------------------------


def walk_term(term: dict[str, Any]) -> dict[str, Any]:
    t = term["type"]

    if t in ("boolean", "number", "string", "null"):
        return {"type": "value", "value": term["value"]}

    if t == "ref":
        path = _ref_to_path(term["value"])
        return {"type": "ref", "path": path}

    if t == "var":
        return {"type": "ref", "path": [term["value"]]}

    if t == "array":
        return {"type": "value", "value": [walk_term_as_jsonvalue(x) for x in term["value"]]}

    if t == "set":
        # zopa's `set` AST node carries plain JSON values as items.
        return {"type": "set", "items": [walk_term_as_jsonvalue(x) for x in term["value"]]}

    if t == "object":
        # OPA encodes object literals as a list of [key_term, value_term]
        # pairs. zopa's Value.object requires string keys.
        members: dict[str, Any] = {}
        for pair in term["value"]:
            key_term, val_term = pair
            if key_term.get("type") != "string":
                raise Unsupported(
                    f"object literal with non-string key (type={key_term.get('type')})"
                )
            members[key_term["value"]] = walk_term_as_jsonvalue(val_term)
        return {"type": "value", "value": members}

    if t == "call":
        return walk_call_form(term["value"])

    raise Unsupported(f"unsupported term type: {t}")


def walk_term_as_value(term: dict[str, Any]) -> dict[str, Any]:
    """Walk a term that's used in `value` position (not body). Same
    as `walk_term` but rejects expressions that wouldn't make sense
    as a literal -- we fold call/iterator/etc. through the regular
    walker since the evaluator supports them in value position too."""
    return walk_term(term)


def walk_term_as_jsonvalue(term: dict[str, Any]) -> Any:
    """Walk a term that's known to be a literal JSON value (e.g.
    inside an array / set literal, or an object value)."""
    t = term["type"]
    if t in ("boolean", "number", "string", "null"):
        return term["value"]
    if t == "array":
        return [walk_term_as_jsonvalue(x) for x in term["value"]]
    if t == "set":
        # JSON has no native set; flatten to a list. The outer caller
        # decides what to do with it. zopa's `set` AST node is built
        # via `walk_term` (above), not here.
        return [walk_term_as_jsonvalue(x) for x in term["value"]]
    if t == "object":
        out: dict[str, Any] = {}
        for pair in term["value"]:
            key_term, val_term = pair
            if key_term.get("type") != "string":
                raise Unsupported(
                    f"object literal with non-string key (type={key_term.get('type')})"
                )
            out[key_term["value"]] = walk_term_as_jsonvalue(val_term)
        return out
    raise Unsupported(f"non-literal term {t} inside array literal")


def _ref_to_path(segments: list[dict[str, Any]]) -> list[str]:
    path: list[str] = []
    for seg in segments:
        t = seg["type"]
        if t == "var":
            path.append(seg["value"])
        elif t == "string":
            path.append(seg["value"])
        elif t == "number":
            # zopa refs are string segments only. Number indices into
            # arrays would need a separate AST shape; out of scope for v1.
            raise Unsupported("numeric ref segment (array index) not supported")
        else:
            raise Unsupported(f"unsupported ref segment type: {t}")
    return path


def _describe_ref(term: dict[str, Any]) -> str:
    """Best-effort name for an operator `_flat_var_name` cannot flatten.

    Multi-segment refs are how OPA spells the operators that have no bare
    name -- `in` arrives as `internal.member_2`. Reporting an empty
    string there tells the reader nothing about what was rejected.
    """
    segs = term.get("value") or []
    parts = [str(seg.get("value")) for seg in segs if isinstance(seg, dict) and "value" in seg]
    return ".".join(parts) if parts else "<unnamed>"


def _flat_var_name(term: dict[str, Any]) -> str:
    if term.get("type") != "ref":
        return ""
    segs = term.get("value", [])
    if len(segs) != 1 or segs[0].get("type") != "var":
        return ""
    return segs[0]["value"]


# ---------------------------------------------------------------------------
# CLI entry.
# ---------------------------------------------------------------------------


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        json.dump({"error": "empty stdin"}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    try:
        opa_module = json.loads(raw)
    except json.JSONDecodeError as e:
        json.dump({"error": f"invalid input json: {e}"}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    try:
        zopa_ast = walk_module(opa_module)
    except Unsupported as e:
        json.dump({"error": "unsupported", "detail": str(e)}, sys.stderr)
        sys.stderr.write("\n")
        return 3

    json.dump(zopa_ast, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
