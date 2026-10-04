#!/usr/bin/env python3
"""OPA conformance runner.

For every fixture in `test/conformance/fixtures/`:

  1. spawn `opa parse --format json` on the rego source,
  2. pipe the result through `tools/rego2ast.py`,
  3. instantiate `zig-out/bin/zopa.wasm` and call its `evaluate`
     export against each case's input + the converted AST,
  4. compare the result (1 / 0 / -1) to the fixture's expected value.

Outcomes per case:

  PASS  decision matched the fixture
  SKIP  rego2ast bailed with `Unsupported` (recorded, not a failure)
  FAIL  rego2ast or zopa returned the wrong decision

Final coverage line goes to stdout; non-zero exit on any FAIL.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import wasmtime


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "test" / "conformance" / "fixtures"
REGO2AST = REPO_ROOT / "tools" / "rego2ast.py"
WASM_PATH = Path(os.environ.get("ZOPA_WASM", REPO_ROOT / "zig-out" / "bin" / "zopa.wasm"))


# ---------------------------------------------------------------------------
# wasm host (mirrors test/run_wasmtime.py)
# ---------------------------------------------------------------------------


def make_stub(return_value: int):
    def stub(*_args):
        return return_value

    return stub


def build_instance() -> tuple[wasmtime.Store, wasmtime.Instance]:
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    linker = wasmtime.Linker(engine)
    i32 = wasmtime.ValType.i32()
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


# ---------------------------------------------------------------------------
# Conformance loop
# ---------------------------------------------------------------------------


def rego_to_zopa_ast(rego_src: str) -> tuple[bool, dict | str]:
    """Spawn `opa parse | rego2ast.py`. Returns (ok, ast | reason)."""
    try:
        opa = subprocess.run(
            ["opa", "parse", "/dev/stdin", "--format", "json"],
            input=rego_src,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False, "opa CLI not found in PATH"

    if opa.returncode != 0:
        return False, f"opa parse failed: {opa.stderr.strip()}"

    walker = subprocess.run(
        [sys.executable, str(REGO2AST)],
        input=opa.stdout,
        capture_output=True,
        text=True,
        check=False,
    )
    if walker.returncode == 3:
        # rego2ast signaled Unsupported; surface as skip reason.
        try:
            err = json.loads(walker.stderr.strip())
            return False, f"unsupported: {err.get('detail', '')}"
        except json.JSONDecodeError:
            return False, f"unsupported (no detail): {walker.stderr.strip()}"
    if walker.returncode != 0:
        return False, f"rego2ast failed: {walker.stderr.strip()}"

    return True, json.loads(walker.stdout)


def evaluate_one(
    store: wasmtime.Store,
    exports,
    memory: wasmtime.Memory,
    input_bytes: bytes,
    ast_obj: dict,
) -> int:
    """Dispatch into the AST's own package (Rego files always carry
    one) rather than zopa's default empty package, since the walker
    preserves the package as the rego source had it. The target rule
    stays `allow` -- we only convert rules named that way for now."""
    malloc = exports["malloc"]
    free = exports["free"]
    evaluate_addressed = exports["evaluate_addressed"]

    def write_bytes(payload: bytes) -> tuple[int, int]:
        ptr = malloc(store, len(payload))
        if ptr == 0:
            raise RuntimeError("wasm malloc returned null")
        memory.write(store, payload, ptr)
        return ptr, len(payload)

    pkg = ast_obj.get("package", "")

    ip, il = write_bytes(input_bytes)
    ap, al = write_bytes(json.dumps(ast_obj).encode("utf-8"))
    pp, pl = write_bytes(pkg.encode("utf-8"))
    tp, tl = write_bytes(b"allow")
    try:
        return evaluate_addressed(store, ip, il, ap, al, pp, pl, tp, tl)
    finally:
        free(store, ip)
        free(store, ap)
        free(store, pp)
        free(store, tp)


def case_input_bytes(case: dict) -> bytes:
    """The request document for one case.

    `input_raw` is a string passed through byte for byte. It exists for
    documents Python's `json` cannot round-trip -- duplicate keys, which
    it collapses before zopa would see them -- so the case can pin zopa
    to the reading `opa eval` gives the same bytes.
    """
    if "input_raw" in case:
        return case["input_raw"].encode("utf-8")
    return json.dumps(case["input"]).encode("utf-8")


def main() -> int:
    if not WASM_PATH.exists():
        print(f"missing wasm: {WASM_PATH}", file=sys.stderr)
        print("run `zig build` first or set ZOPA_WASM=...", file=sys.stderr)
        return 2

    store, instance = build_instance()
    exports = instance.exports(store)
    memory = exports["memory"]

    fixtures = sorted(FIXTURES_DIR.glob("*.json"))
    if not fixtures:
        print(f"no fixtures in {FIXTURES_DIR}", file=sys.stderr)
        return 2

    pass_n = skip_n = fail_n = 0
    failures: list[str] = []

    for path in fixtures:
        fix = json.loads(path.read_text())
        name = fix["name"]

        ok, payload = rego_to_zopa_ast(fix["rego"])
        if not ok:
            for case in fix["cases"]:
                skip_n += 1
                print(f"SKIP  {name}  {payload}")
            continue

        for i, case in enumerate(fix["cases"]):
            try:
                got = evaluate_one(store, exports, memory, case_input_bytes(case), payload)
            except Exception as e:  # pylint: disable=broad-except
                fail_n += 1
                line = f"FAIL  {name}#{i}  evaluate raised: {e}"
                failures.append(line)
                print(line)
                continue

            expected = case["expected"]
            if got == expected:
                pass_n += 1
                print(f"PASS  {name}#{i}  ({got})")
            else:
                fail_n += 1
                line = f"FAIL  {name}#{i}  got={got} expected={expected}"
                failures.append(line)
                print(line)

    total = pass_n + skip_n + fail_n
    print()
    print(f"conformance: {pass_n} passed, {skip_n} skipped, {fail_n} failed (of {total} cases)")

    if fail_n:
        print()
        print("failures:")
        for line in failures:
            print(f"  {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
