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
import re
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

# Largest array index zopa's AST builder accepts (Expr.max_path_index in
# src/ast.zig). Fixed rather than platform-dependent so the converter
# and the module agree regardless of where each one runs.
MAX_PATH_INDEX = 2**32 - 1


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

    # `allow if a else = false if b` is one Rule whose head and body
    # cover the first branch only; the fallback hangs off `rule["else"]`
    # as another Rule, chainable further. Nothing here reads it, so
    # converting would emit the first condition alone -- dropping a deny
    # path or an allow path depending on which branch was the fallback.
    if rule.get("else") is not None:
        raise Unsupported(
            f"`else` on rule `{name}` not supported: the fallback branch would be dropped"
        )

    # A function definition -- `f(x) if x == 1` -- carries its
    # parameters in `head["args"]`. zopa rules take no arguments, and
    # without this the parameter converts into a bare ref that resolves
    # against the input document instead of a binding, so `f(x)` would
    # silently become a test on `input.x`.
    #
    # A *nullary* definition, `f() if ...`, is not detectable here and
    # is not guarded: OPA emits a head byte-identical to the plain rule
    # `f if ...` -- no `args` key on either -- so there is nothing to
    # branch on. It converts into a rule named `f`, addressable as data
    # where OPA's function is not. Reaching that requires defining
    # `f()`, never calling it (the call site is refused as an
    # unsupported call), then targeting `f` directly. Recorded in
    # docs/ast.md and pinned by a test rather than papered over.
    if head.get("args"):
        raise Unsupported(
            f"function definition `{name}` not supported: "
            "zopa rules take no parameters, so the arguments would resolve against the input"
        )

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
    body = walk_body(rule.get("body", []))

    out["body"] = body

    head_val = head.get("value")
    if head_val is not None and not _is_literal_true(head_val):
        # `allow := y if { y := input.q }` reads `y` from the body. zopa
        # evaluates a rule's value outside the body's scope, so the ref
        # would resolve against the input root instead -- undefined on
        # every request, a rule that never yields what OPA yields.
        bound = sorted(_body_bindings(body) & _var_names(head_val))
        if bound:
            raise Unsupported(
                f"rule `{name}` returns body binding `{bound[0]}`: "
                "zopa evaluates the rule value outside the body's scope"
            )
        out["value"] = walk_term_as_value(head_val)

    _check_scope(out["body"], frozenset())
    if "value" in out:
        _check_expr_scope(out["value"], frozenset())
    return out


# zopa resolves a ref whose head is not a binding in scope against the
# input root -- `ref ["is_admin"]` reads `input.is_admin`. A Rego name
# that is neither `input` nor bound by then is something else: another
# rule (`allow if is_admin`), the `data` document, or a name used before
# its declaration. Converting any of them lets the request supply the
# value: `{"is_admin": true}` allowed where `opa eval` is undefined.
# Checked on the emitted AST, where the scoping is the evaluator's.
def _check_scope(body: list[dict[str, Any]], scope: frozenset[str]) -> None:
    for expr in body:
        _check_expr_scope(expr, scope)
        if expr.get("type") == "assign":
            scope = scope | {expr["var"]}


def _check_expr_scope(expr: dict[str, Any], scope: frozenset[str]) -> None:
    t = expr.get("type")
    if t == "ref":
        head = expr["path"][0]
        if head != "input" and head not in scope:
            raise Unsupported(
                f"`{head}` is not `input` or a name bound at this point: references to other "
                "rules, to `data`, or to a name before its declaration would be read from the input"
            )
    elif t in ("compare", "in"):
        _check_expr_scope(expr["left"], scope)
        _check_expr_scope(expr["right"], scope)
    elif t == "not":
        _check_expr_scope(expr["expr"], scope)
    elif t == "call":
        for a in expr["args"]:
            _check_expr_scope(a, scope)
    elif t == "assign":
        _check_expr_scope(expr["value"], scope)
    elif t in ("some", "every"):
        _check_expr_scope(expr["source"], scope)
        body = expr["body"]
        _check_scope(body if isinstance(body, list) else [body], scope | {expr["var"]})


def _body_bindings(body: list[dict[str, Any]]) -> set[str]:
    """Names a rule body binds at its own scope, as zopa AST.

    A standalone `some` nests the rest of the body inside itself, but
    in Rego those statements are still the rule's own scope, so the walk
    follows list-bodied `some`s down. `every` is a scope of its own and
    is not followed. The converter emits no other list-bodied `some`.
    """
    names: set[str] = set()
    for expr in body:
        if expr.get("type") == "assign":
            names.add(expr["var"])
        elif expr.get("type") == "some" and isinstance(expr.get("body"), list):
            names.add(expr["var"])
            names |= _body_bindings(expr["body"])
    return names


def walk_body(
    exprs: list[dict[str, Any]], claimed: frozenset[str] = frozenset()
) -> list[dict[str, Any]]:
    """Convert one Rego body -- a rule's, or an `every`'s -- into a
    zopa statement list.

    A standalone `some x in xs` binds `x` for every statement after it.
    zopa's `some` owns the body it binds over, so the declaration becomes
    a `some` whose body is the rest of this one. Statements before it
    stay outside, and their assignments stay visible inside: the
    evaluator runs the `some` within the frames they push.
    """
    # Rego's `:=` and `some` share one namespace per scope: `opa check`
    # refuses `x := 1; x := 2` as "var x assigned above" and a repeated
    # or reassigned `some` name as "var x declared above". This pipeline
    # runs `opa parse`, which accepts both, and once a `some` nests the
    # rest of the body the module's own per-list check cannot see across
    # the nesting -- so the converter checks the flat statement list.
    # `claimed` carries names the enclosing construct binds in this same
    # scope -- an `every`'s own variable, which OPA refuses to redeclare
    # in its body. Names from enclosing scopes may be shadowed and are
    # not passed.
    seen: dict[str, str] = {name: "some" for name in claimed}

    def claim(name: str, how: str) -> None:
        if re.fullmatch(r"\$\d+", name):
            return  # a wildcard, `_`, which OPA renames and nothing can read
        if name in seen:
            if how == "assign" and seen[name] == "assign":
                raise Unsupported(
                    f"`{name}` is assigned twice in one body; "
                    "Rego allows a name to be bound once per scope"
                )
            raise Unsupported(
                f"`{name}` is declared twice in one body; "
                "Rego allows a name to be bound once per scope"
            )
        seen[name] = how

    for expr in exprs:
        for name, how in _rego_bindings(expr):
            claim(name, how)

    out: list[dict[str, Any]] = []
    for i, expr in enumerate(exprs):
        terms = expr.get("terms")
        if isinstance(terms, dict) and "symbols" in terms:
            if expr.get("with"):
                raise Unsupported(
                    "`with` modifier not supported: it would change the input the body sees"
                )
            var, source = _some_in_declaration(terms["symbols"])
            out.append({
                "type": "some",
                "var": var,
                "source": source,
                # Rego binds an object's *values* here, as for `every`.
                "kind": "values",
                "body": walk_body(exprs[i + 1 :]),
            })
            return out
        out.append(walk_expr(expr))
    return out


def _rego_bindings(expr: dict[str, Any]) -> list[tuple[str, str]]:
    """Names a Rego statement binds at its own scope: an assignment's
    target, or the names a `some` declares. `every` binds inside a scope
    of its own. Shapes `walk_body` goes on to refuse yield nothing here;
    the refusal comes from the walk with a better message."""
    terms = expr.get("terms")
    if isinstance(terms, dict) and "symbols" in terms:
        names: list[tuple[str, str]] = []
        for decl in terms["symbols"]:
            if decl.get("type") == "var":
                names.append((decl["value"], "some"))
            elif decl.get("type") == "call":
                names.extend(
                    (a["value"], "some") for a in decl["value"][1:-1] if a.get("type") == "var"
                )
        return names
    if (
        isinstance(terms, list)
        and len(terms) == 3
        and _flat_var_name(terms[0]) == "assign"
        and terms[1].get("type") == "var"
    ):
        return [(terms[1]["value"], "assign")]
    return []


def _some_in_declaration(symbols: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """`some x in xs` -> (`x`, zopa source). The other declaration
    shapes stay refused, each for a reason that would otherwise convert
    into a different policy."""
    if len(symbols) != 1:
        raise Unsupported("`some` declaring several names at once not supported")
    decl = symbols[0]
    if decl.get("type") != "call":
        # `some x` with no domain: the name is bound by unification with
        # whatever later refs it appears in, e.g. `input.xs[x]`. zopa has
        # no unification, and the bare var would resolve against the input.
        raise Unsupported(
            "`some x` without `in` not supported: zopa binds names by iteration, not unification"
        )
    op = _describe_ref(decl["value"][0])
    args = decl["value"][1:]
    if op == "internal.member_3":
        raise Unsupported(
            "`some k, v in xs` not supported: zopa binds one variable per iteration"
        )
    if op != "internal.member_2" or len(args) != 2:
        raise Unsupported(f"unrecognized `some` declaration: {op}")
    target = args[0]
    if target.get("type") != "var":
        raise Unsupported(
            "`some` target must be a plain variable; destructuring is not supported"
        )
    return target["value"], walk_term(args[1])


def _var_names(term: Any) -> set[str]:
    """Every variable an OPA term mentions, at any depth."""
    names: set[str] = set()
    if isinstance(term, dict):
        if term.get("type") == "var" and isinstance(term.get("value"), str):
            names.add(term["value"])
        for v in term.values():
            names |= _var_names(v)
    elif isinstance(term, list):
        for v in term:
            names |= _var_names(v)
    return names


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
        # A `some` declaration is a body statement, which `walk_body`
        # converts before it gets here. Reaching this means it sat
        # somewhere without a body to scope over. Without the check the
        # dict falls through to `walk_term`, which reaches for a "type"
        # key a declaration does not have and dies with a KeyError -- a
        # traceback where the runner expects an AST or a clean refusal.
        if "symbols" in terms:
            raise Unsupported("`some` declaration outside a body")
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

    if op_name == "assign":
        # `x := <expr>`. OPA spells it as a two-argument call whose
        # first argument is the variable being bound.
        if len(args) != 2:
            raise Unsupported(f"assign expects 2 args, got {len(args)}")
        target = args[0]
        if target.get("type") != "var":
            raise Unsupported(
                "assignment target must be a plain variable; destructuring is not supported"
            )
        name = target["value"]
        # OPA rewrites `_` and some desugared forms into generated names
        # like `__local0__`. Those come from constructs zopa refuses
        # elsewhere, so seeing one here means something was desugared
        # into an assignment rather than written as one.
        if name.startswith("__") or name == "_":
            raise Unsupported(f"generated assignment target `{name}` (desugared construct)")
        return {
            "type": "assign",
            "var": name,
            "value": walk_term(args[1]),
        }

    if _describe_ref(op_ref) == "internal.member_2":
        # `x in xs`. The three-argument form, `k, v in xs`, arrives as
        # `internal.member_3` and stays unsupported: it binds a key too.
        if len(args) != 2:
            raise Unsupported(f"`in` expects 2 args, got {len(args)}")
        return {
            "type": "in",
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
    value = terms.get("value")
    if value is None or value.get("type") != "var":
        raise Unsupported("every: missing iteration variable name")
    body_exprs = walk_body(terms.get("body", []), frozenset({value["value"]}))
    # One plain expression keeps the single-expression form; anything
    # else -- several statements, or a lone binding the object form
    # would refuse -- goes out as a statement list.
    if len(body_exprs) == 1 and body_exprs[0].get("type") != "assign":
        body_inner: Any = body_exprs[0]
    else:
        body_inner = body_exprs

    # `every k, v in xs` binds the key as well. zopa's `every` binds one
    # variable, and dropping `k` would leave it a bare ref resolving
    # against the input. A wildcard (`_`, which OPA renames `$0`) binds
    # nothing and is fine.
    key = terms.get("key")
    key_name = key.get("value") if isinstance(key, dict) else None
    if key is not None and not (
        key.get("type") == "var" and isinstance(key_name, str) and re.fullmatch(r"\$\d+", key_name)
    ):
        raise Unsupported("`every` with a key binding not supported: zopa binds one variable")

    out: dict[str, Any] = {
        "type": "every",
        "var": value["value"],
        "source": domain,
        "body": body_inner,
        # Rego binds an object's *values* here. zopa's AST defaults to
        # keys when `kind` is absent, so leaving it out converted
        # `every v in obj { v != "x" }` into a check of the keys.
        # Arrays and sets ignore `kind`.
        "kind": "values",
    }
    return out


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

    # OPA spells a null term `{"type": "null", "value": {}}`: its value
    # is an empty object, not None. Passing it through turned
    # `input.x == null` into a comparison against `{}`.
    if t == "null":
        return {"type": "value", "value": None}
    if t in ("boolean", "number", "string"):
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
    if t == "null":
        return None
    if t in ("boolean", "number", "string"):
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


def _ref_to_path(segments: list[dict[str, Any]]) -> list[str | int]:
    """Flatten an OPA ref into zopa's path array.

    The head var (`input`, or a bound name) and string segments become
    key segments; a number becomes an array index, which zopa's `ref`
    encodes as a JSON number in the same array. The two stay distinct
    end to end -- an index never matches an object key that happens to
    spell the same digits.
    """
    path: list[str | int] = []
    for i, seg in enumerate(segments):
        t = seg["type"]
        if t == "var":
            # Past the head, a var is a lookup by the variable's *value*
            # -- `input.xs[i]`, or `input.xs[_]` (OPA renames `_` to
            # `$0`). zopa's path segments are literals, so appending the
            # name looked up the key "i": `every i in input.idx {
            # input.xs[i] == 1 }` allowed `{"idx": [0], "xs": {"i": 1}}`,
            # which OPA denies.
            if i > 0:
                raise Unsupported(
                    f"variable `{seg['value']}` inside a ref not supported: "
                    "zopa ref segments are literal keys and indices"
                )
            path.append(seg["value"])
        elif t == "string":
            path.append(seg["value"])
        elif t == "number":
            value = seg["value"]
            # Rego permits `xs[-1]` and `xs[1.5]` syntactically; both are
            # undefined at evaluation. zopa rejects them when the AST is
            # built, so refuse here rather than emitting a path the
            # module will not accept.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise Unsupported(f"non-numeric array index: {value!r}")
            if value < 0 or value != int(value):
                raise Unsupported(
                    f"array index must be a whole non-negative number, got {value!r}"
                )
            # Same ceiling ast.zig enforces. Python ints are unbounded,
            # so without this a legal-but-absurd literal like
            # `input.xs[99999999999999999999]` converts here and is
            # refused later by the module as a bare InvalidPath -- the
            # one rejection in this walker that would not carry a
            # described reason.
            if value > MAX_PATH_INDEX:
                raise Unsupported(
                    f"array index above the maximum zopa accepts ({MAX_PATH_INDEX}): {int(value)}"
                )
            path.append(int(value))
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
