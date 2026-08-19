#!/usr/bin/env python3
"""Wasmtime-driven integration tests for zopa.wasm.

The same suite as test/run.mjs against a different runtime, to surface
host-specific quirks before they hit a real embedder.

    .venv-test/bin/python test/run_wasmtime.py
    zig build test-wasmtime
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import wasmtime


WASM_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("zig-out/bin/zopa.wasm")


def make_stub(return_value: int):
    """Stub callable for `Linker.define_func`. proxy-wasm imports
    aren't reached by the generic-ABI tests; a fired stub means the
    harness drifted."""

    def stub(*_args):
        return return_value

    return stub


def build_instance() -> tuple[wasmtime.Store, wasmtime.Instance]:
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    linker = wasmtime.Linker(engine)

    i32 = wasmtime.ValType.i32()
    # Every proxy-wasm import declared in src/proxy_wasm.zig must
    # resolve, even though we don't call them here.
    imports: list[tuple[str, list[wasmtime.ValType], int]] = [
        ("proxy_log", [i32, i32, i32], 0),
        ("proxy_get_buffer_bytes", [i32, i32, i32, i32, i32], 1),
        ("proxy_get_header_map_pairs", [i32, i32, i32], 1),
        ("proxy_get_header_map_value", [i32, i32, i32, i32, i32], 1),
        ("proxy_send_local_response", [i32] * 8, 0),
    ]
    for name, params, ret in imports:
        ftype = wasmtime.FuncType(params, [i32])
        linker.define_func("env", name, ftype, make_stub(ret))

    module = wasmtime.Module.from_file(engine, str(WASM_PATH))
    instance = linker.instantiate(store, module)
    return store, instance


store, instance = build_instance()
exports = instance.exports(store)
malloc = exports["malloc"]
free = exports["free"]
evaluate = exports["evaluate"]
evaluate_target = exports["evaluate_target"]
evaluate_addressed = exports["evaluate_addressed"]
memory: wasmtime.Memory = exports["memory"]


def write_bytes(payload: bytes) -> tuple[int, int]:
    """Allocate inside wasm linear memory and copy the payload in.
    Returns `(ptr, len)`. The caller frees `ptr` via `free(store, ptr)`."""
    size = len(payload)
    ptr = malloc(store, size)
    if ptr == 0:
        raise RuntimeError("wasm malloc returned null")
    memory.write(store, payload, ptr)
    return ptr, size


def write_json(obj) -> tuple[int, int]:
    return write_bytes(json.dumps(obj).encode("utf-8"))


def decide(input_obj, ast_obj) -> int:
    ip, il = write_json(input_obj)
    ap, al = write_json(ast_obj)
    try:
        return evaluate(store, ip, il, ap, al)
    finally:
        free(store, ip)
        free(store, ap)


def decide_target(input_obj, ast_obj, target: str) -> int:
    ip, il = write_json(input_obj)
    ap, al = write_json(ast_obj)
    tp, tl = write_bytes(target.encode("utf-8"))
    try:
        return evaluate_target(store, ip, il, ap, al, tp, tl)
    finally:
        free(store, ip)
        free(store, ap)
        free(store, tp)


def decide_addressed(input_obj, ast_obj, package: str, target: str) -> int:
    ip, il = write_json(input_obj)
    ap, al = write_json(ast_obj)
    pp, pl = write_bytes(package.encode("utf-8"))
    tp, tl = write_bytes(target.encode("utf-8"))
    try:
        return evaluate_addressed(store, ip, il, ap, al, pp, pl, tp, tl)
    finally:
        free(store, ip)
        free(store, ap)
        free(store, pp)
        free(store, tp)


def decide_raw(input_bytes: bytes, ast_obj) -> int:
    """Decide against input bytes that json.dumps would not produce --
    duplicate keys and non-JSON number literals have to be hand-written
    to be testable at all."""
    ip, il = write_bytes(input_bytes)
    ap, al = write_json(ast_obj)
    try:
        return evaluate(store, ip, il, ap, al)
    finally:
        free(store, ip)
        free(store, ap)


# ---------------------------------------------------------------------------
# Tiny assertion helper.
# ---------------------------------------------------------------------------

failed = 0


def check(name: str, got, expected):
    global failed
    if got == expected:
        print(f"PASS  {name}")
    else:
        print(f"FAIL  {name}: got {got!r}, expected {expected!r}")
        failed += 1


# ---------------------------------------------------------------------------
# Cases (kept in lockstep with test/run.mjs).
# ---------------------------------------------------------------------------

ref_role = {"type": "ref", "path": ["input", "user", "role"]}
ref_age = {"type": "ref", "path": ["input", "age"]}

check("bare literal true -> allow", decide({}, {"type": "value", "value": True}), 1)
check("bare literal false -> deny", decide({}, {"type": "value", "value": False}), 0)

check(
    "compare eq -> allow",
    decide(
        {"user": {"role": "admin"}},
        {"type": "compare", "op": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}},
    ),
    1,
)
check(
    "compare neq -> allow on mismatch",
    decide(
        {"user": {"role": "guest"}},
        {"type": "compare", "op": "neq", "left": ref_role, "right": {"type": "value", "value": "admin"}},
    ),
    1,
)

check(
    "compare lt -> allow",
    decide({"age": 17}, {"type": "compare", "op": "lt", "left": ref_age, "right": {"type": "value", "value": 18}}),
    1,
)
check(
    "compare gte -> allow at boundary",
    decide({"age": 18}, {"type": "compare", "op": "gte", "left": ref_age, "right": {"type": "value", "value": 18}}),
    1,
)

check(
    "not flips false to allow",
    decide({"admin": False}, {"type": "not", "expr": {"type": "ref", "path": ["input", "admin"]}}),
    1,
)

admin_policy = {
    "type": "module",
    "rules": [
        {"type": "rule", "name": "allow", "default": True, "value": {"type": "value", "value": False}},
        {
            "type": "rule",
            "name": "allow",
            "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}}],
        },
    ],
}
check("module default deny when not admin", decide({"user": {"role": "guest"}}, admin_policy), 0)
check("module rule fires when admin", decide({"user": {"role": "admin"}}, admin_policy), 1)

age_gate = {
    "type": "module",
    "rules": [
        {
            "type": "rule",
            "name": "allow",
            "body": [{"type": "value", "value": True}],
            "value": {"type": "compare", "op": "gte", "left": ref_age, "right": {"type": "value", "value": 18}},
        },
    ],
}
check("nested compare in value: 25 >= 18 -> allow", decide({"age": 25}, age_gate), 1)
check("nested compare in value: 12 >= 18 -> deny", decide({"age": 12}, age_gate), 0)

# Surrogate pair: U+1D11E (musical symbol G clef). Round-trip via JSON
# escape on the AST side and the actual codepoint on the input side.
input_ptr_size = write_bytes(json.dumps({"name": "\U0001D11E"}).encode("utf-8"))
ast_text = (
    '{"type":"compare","op":"eq",'
    '"left":{"type":"ref","path":["input","name"]},'
    '"right":{"type":"value","value":"\\uD834\\uDD1E"}}'
)
ast_ptr_size = write_bytes(ast_text.encode("utf-8"))
result = evaluate(store, input_ptr_size[0], input_ptr_size[1], ast_ptr_size[0], ast_ptr_size[1])
free(store, input_ptr_size[0])
free(store, ast_ptr_size[0])
check("surrogate-pair literal equals U+1D11E in input", result, 1)

# Nested `not` past the depth cap.
nested = {"type": "value", "value": True}
for _ in range(64):
    nested = {"type": "not", "expr": nested}
check("64 nested nots trip depth guard -> -1", decide({}, nested), -1)

# some / every -- match the JS suite.
some_admin = {
    "type": "some",
    "var": "tag",
    "source": {"type": "ref", "path": ["input", "tags"]},
    "body": {"type": "eq", "left": {"type": "ref", "path": ["tag"]}, "right": {"type": "value", "value": "admin"}},
}
check("some: matching element -> allow", decide({"tags": ["viewer", "admin"]}, some_admin), 1)
check("some: no match -> deny", decide({"tags": ["viewer"]}, some_admin), 0)
check("some: empty source -> deny", decide({"tags": []}, some_admin), 0)

every_admin = dict(some_admin, type="every")
check("every: all match -> allow", decide({"tags": ["admin", "admin"]}, every_admin), 1)
check("every: one mismatch -> deny", decide({"tags": ["admin", "guest"]}, every_admin), 0)
check("every: vacuously true on empty -> allow", decide({"tags": []}, every_admin), 1)

every_some = {
    "type": "every",
    "var": "required",
    "source": {"type": "ref", "path": ["input", "required_perms"]},
    "body": {
        "type": "some",
        "var": "granted",
        "source": {"type": "ref", "path": ["input", "user", "perms"]},
        "body": {
            "type": "eq",
            "left": {"type": "ref", "path": ["granted"]},
            "right": {"type": "ref", "path": ["required"]},
        },
    },
}
check(
    "every+some: user has every required perm -> allow",
    decide({"required_perms": ["read", "write"], "user": {"perms": ["read", "write", "admin"]}}, every_some),
    1,
)
check(
    "every+some: missing one required perm -> deny",
    decide({"required_perms": ["read", "delete"], "user": {"perms": ["read", "write"]}}, every_some),
    0,
)

# ---------------------------------------------------------------------------
# 8. call: builtin functions (startswith / endswith / contains / count)
# ---------------------------------------------------------------------------
check(
    "call startswith on input.path -> allow",
    decide({"path": "/admin/users"}, {
        "type": "call", "name": "startswith",
        "args": [
            {"type": "ref", "path": ["input", "path"]},
            {"type": "value", "value": "/admin/"},
        ],
    }),
    1,
)
check(
    "call startswith on input.path -> deny",
    decide({"path": "/users"}, {
        "type": "call", "name": "startswith",
        "args": [
            {"type": "ref", "path": ["input", "path"]},
            {"type": "value", "value": "/admin/"},
        ],
    }),
    0,
)
check(
    "call endswith on host -> allow",
    decide({"host": "api.internal"}, {
        "type": "call", "name": "endswith",
        "args": [
            {"type": "ref", "path": ["input", "host"]},
            {"type": "value", "value": ".internal"},
        ],
    }),
    1,
)
check(
    "call contains in user-agent -> allow",
    decide({"ua": "Mozilla/5.0 Bot"}, {
        "type": "call", "name": "contains",
        "args": [
            {"type": "ref", "path": ["input", "ua"]},
            {"type": "value", "value": "Bot"},
        ],
    }),
    1,
)
check(
    "call count > 2 over array -> allow",
    decide({"perms": ["r", "w", "x"]}, {
        "type": "gt",
        "left": {"type": "call", "name": "count", "args": [{"type": "ref", "path": ["input", "perms"]}]},
        "right": {"type": "value", "value": 2},
    }),
    1,
)
check(
    "call unknown builtin -> deny",
    decide({}, {"type": "call", "name": "made_up_function", "args": [{"type": "value", "value": 1}]}),
    0,
)

# ---------------------------------------------------------------------------
# 9. some / every over object refs (kind: keys / values, default keys)
# ---------------------------------------------------------------------------
every_key_not_internal = {
    "type": "every", "var": "k", "kind": "keys",
    "source": {"type": "ref", "path": ["input", "attrs"]},
    "body": {
        "type": "neq",
        "left": {"type": "ref", "path": ["k"]},
        "right": {"type": "value", "value": "internal"},
    },
}
check(
    "every over object keys: no banned key -> allow",
    decide({"attrs": {"team": "sre", "region": "us-east"}}, every_key_not_internal),
    1,
)
check(
    "every over object keys: banned key present -> deny",
    decide({"attrs": {"team": "sre", "internal": "yes"}}, every_key_not_internal),
    0,
)

some_value_true = {
    "type": "some", "var": "v", "kind": "values",
    "source": {"type": "ref", "path": ["input", "flags"]},
    "body": {
        "type": "eq",
        "left": {"type": "ref", "path": ["v"]},
        "right": {"type": "value", "value": True},
    },
}
check(
    "some over object values: at least one true -> allow",
    decide({"flags": {"a": False, "b": True, "c": False}}, some_value_true),
    1,
)
check(
    "some over object values: all false -> deny",
    decide({"flags": {"a": False, "b": False}}, some_value_true),
    0,
)

# `kind` defaults to "keys" when omitted on an object source.
every_default_keys = {
    "type": "every", "var": "k",
    "source": {"type": "ref", "path": ["input", "m"]},
    "body": {
        "type": "neq",
        "left": {"type": "ref", "path": ["k"]},
        "right": {"type": "value", "value": "banned"},
    },
}
check(
    "every over object defaults to keys: clean -> allow",
    decide({"m": {"x": 1, "y": 2}}, every_default_keys),
    1,
)
check(
    "every over object defaults to keys: banned -> deny",
    decide({"m": {"x": 1, "banned": 2}}, every_default_keys),
    0,
)

# ---------------------------------------------------------------------------
# 10. modules bundle: package addressing (default entry point only)
# ---------------------------------------------------------------------------
wrapped_module = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}}],
                }
            ],
        }
    ],
}
check("modules bundle: empty package -> allow when admin", decide({"user": {"role": "admin"}}, wrapped_module), 1)
check("modules bundle: empty package -> deny when guest", decide({"user": {"role": "guest"}}, wrapped_module), 0)

two_packages = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}}],
                }
            ],
        },
        {
            "type": "module",
            "package": "audit",
            "rules": [{"type": "rule", "name": "allow", "body": [{"type": "value", "value": True}]}],
        },
    ],
}
check("modules bundle: default entry picks empty package", decide({"user": {"role": "admin"}}, two_packages), 1)
check("modules bundle: audit module invisible from default entry", decide({"user": {"role": "guest"}}, two_packages), 0)

# ---------------------------------------------------------------------------
# 11. evaluate_target: response-side rules via the explicit-target export.
# ---------------------------------------------------------------------------
response_policy = {
    "type": "module",
    "rules": [
        {"type": "rule", "name": "allow_response", "default": True, "value": {"type": "value", "value": True}},
        {
            "type": "rule",
            "name": "allow_response",
            "body": [
                {
                    "type": "gte",
                    "left": {"type": "ref", "path": ["input", "response", "status"]},
                    "right": {"type": "value", "value": 500},
                }
            ],
            "value": {"type": "value", "value": False},
        },
    ],
}
check(
    "evaluate_target allow_response: 500 -> deny",
    decide_target({"response": {"status": 500, "headers": {}}}, response_policy, "allow_response"),
    0,
)
check(
    "evaluate_target allow_response: 200 -> allow",
    decide_target({"response": {"status": 200, "headers": {}}}, response_policy, "allow_response"),
    1,
)
check(
    "evaluate_target with missing target rule -> deny",
    decide_target({}, {"type": "value", "value": True}, "allow_response"),
    0,
)

# ---------------------------------------------------------------------------
# 12. evaluate_target: body-side rules via the explicit-target export.
# ---------------------------------------------------------------------------
body_policy = {
    "type": "module",
    "rules": [
        {"type": "rule", "name": "allow_body", "default": True, "value": {"type": "value", "value": True}},
        {
            "type": "rule",
            "name": "allow_body",
            "body": [
                {
                    "type": "gt",
                    "left": {"type": "ref", "path": ["input", "body", "amount"]},
                    "right": {"type": "value", "value": 1000},
                }
            ],
            "value": {"type": "value", "value": False},
        },
    ],
}
check(
    "evaluate_target allow_body: amount over limit -> deny",
    decide_target({"body": {"amount": 5000}, "body_raw": "{\"amount\":5000}"}, body_policy, "allow_body"),
    0,
)
check(
    "evaluate_target allow_body: amount under limit -> allow",
    decide_target({"body": {"amount": 50}, "body_raw": "{\"amount\":50}"}, body_policy, "allow_body"),
    1,
)

raw_policy = {
    "type": "module",
    "rules": [
        {
            "type": "rule",
            "name": "allow_body",
            "body": [
                {
                    "type": "eq",
                    "left": {"type": "ref", "path": ["input", "body_raw"]},
                    "right": {"type": "value", "value": "BLOCKED"},
                }
            ],
            "value": {"type": "value", "value": False},
        },
        {"type": "rule", "name": "allow_body", "default": True, "value": {"type": "value", "value": True}},
    ],
}
check(
    "evaluate_target allow_body: body_raw=BLOCKED -> deny",
    decide_target({"body": None, "body_raw": "BLOCKED"}, raw_policy, "allow_body"),
    0,
)
check(
    "evaluate_target allow_body: body_raw=ok -> allow",
    decide_target({"body": None, "body_raw": "ok"}, raw_policy, "allow_body"),
    1,
)

# ---------------------------------------------------------------------------
# Rule dispatch and parser agreement. These carry the highest fail-open
# stakes in the module, so they run under this runtime too rather than
# only under Node.
# ---------------------------------------------------------------------------

addressed_packages = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}}],
                }
            ],
        },
        {
            "type": "module",
            "package": "audit",
            "rules": [{"type": "rule", "name": "allow", "body": [{"type": "value", "value": True}]}],
        },
    ],
}

check(
    "addressed: authz.allow fires for admin",
    decide_addressed({"user": {"role": "admin"}}, addressed_packages, "authz", "allow"),
    1,
)
check(
    "addressed: authz.allow denies a guest",
    decide_addressed({"user": {"role": "guest"}}, addressed_packages, "authz", "allow"),
    0,
)
check(
    "addressed: audit.allow fires regardless of role",
    decide_addressed({"user": {"role": "guest"}}, addressed_packages, "audit", "allow"),
    1,
)
check(
    "addressed: unknown package denies",
    decide_addressed({"user": {"role": "admin"}}, addressed_packages, "nope", "allow"),
    0,
)

# A package split across modules is one rule set: the default declared
# in the first module governs the rule declared in the second.
split_package = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {"type": "rule", "name": "allow", "default": True, "value": {"type": "value", "value": True}}
            ],
        },
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "banned"}}],
                    "value": {"type": "value", "value": False},
                }
            ],
        },
    ],
}

check(
    "split package: sibling module inherits the default -> allow",
    decide_addressed({"user": {"role": "viewer"}}, split_package, "authz", "allow"),
    1,
)
check(
    "split package: deny rule in the second module still fires",
    decide_addressed({"user": {"role": "banned"}}, split_package, "authz", "allow"),
    0,
)

# Two definitions of one complete rule holding at once with different
# values is eval_conflict_error in OPA, not a race the first one wins.
conflicting = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [
                        {
                            "type": "eq",
                            "left": {"type": "ref", "path": ["input", "tenant"]},
                            "right": {"type": "value", "value": "acme"},
                        }
                    ],
                }
            ],
        },
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {
                    "type": "rule",
                    "name": "allow",
                    "body": [{"type": "eq", "left": ref_role, "right": {"type": "value", "value": "banned"}}],
                    "value": {"type": "value", "value": False},
                }
            ],
        },
    ],
}

check(
    "conflicting definitions -> -1 (deny), not first-in-bundle",
    decide_addressed({"tenant": "acme", "user": {"role": "banned"}}, conflicting, "authz", "allow"),
    -1,
)
check(
    "only the allow definition holds -> allow",
    decide_addressed({"tenant": "acme", "user": {"role": "viewer"}}, conflicting, "authz", "allow"),
    1,
)
check(
    "only the deny definition holds -> deny",
    decide_addressed({"tenant": "other", "user": {"role": "banned"}}, conflicting, "authz", "allow"),
    0,
)

# Two `default` declarations for one rule: rego_type_error in OPA,
# rejected when the AST is built here.
duplicate_defaults = {
    "type": "modules",
    "modules": [
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {"type": "rule", "name": "allow", "default": True, "value": {"type": "value", "value": False}}
            ],
        },
        {
            "type": "module",
            "package": "authz",
            "rules": [
                {"type": "rule", "name": "allow", "default": True, "value": {"type": "value", "value": True}}
            ],
        },
    ],
}

check(
    "two defaults for one rule -> -1",
    decide_addressed({}, duplicate_defaults, "authz", "allow"),
    -1,
)

# Parser agreement with the backend. Duplicate keys resolve last-wins in
# Go, JavaScript, and OPA; the number grammar is RFC 8259, not whatever
# a float parser happens to accept.
dup_policy = {"type": "eq", "left": ref_role, "right": {"type": "value", "value": "admin"}}
check(
    "duplicate input keys resolve last-wins -> deny",
    decide_raw(b'{"user":{"role":"admin","role":"guest"}}', dup_policy),
    0,
)

for bad in (b'{"n":01}', b'{"n":1.}', b'{"n":.5}', b'{"n":+1}', b'{"n":1e}'):
    check(
        f"non-JSON number {bad.decode()} is rejected -> -1",
        decide_raw(bad, {"type": "value", "value": True}),
        -1,
    )

# body_truncated is part of the body-phase input shape.
truncation_policy = {
    "type": "module",
    "rules": [
        {"type": "rule", "name": "allow_body", "default": True, "value": {"type": "value", "value": True}},
        {
            "type": "rule",
            "name": "allow_body",
            "body": [{"type": "ref", "path": ["input", "body_truncated"]}],
            "value": {"type": "value", "value": False},
        },
    ],
}
check(
    "body_truncated=true -> policy can deny",
    decide_target(
        {"body": None, "body_raw": '{"a":1', "body_truncated": True},
        truncation_policy,
        "allow_body",
    ),
    0,
)
check(
    "body_truncated=false -> default allows",
    decide_target(
        {"body": {"a": 1}, "body_raw": '{"a":1}', "body_truncated": False},
        truncation_policy,
        "allow_body",
    ),
    1,
)

if failed:
    print(f"\n{failed} test(s) failed", file=sys.stderr)
    sys.exit(1)

print("\nall tests passed")
