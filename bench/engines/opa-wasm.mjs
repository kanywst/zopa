// OPA's WASM build, driven through the `opa_eval` one-shot export.
//
// The binding is hand-rolled rather than taken from
// @open-policy-agent/opa-wasm: this repository has no package.json and
// adding an npm dependency to compare against would make the benchmark
// harder to run than the thing it measures. The ABI used here is the
// documented one (opa_wasm_abi_version 1, minor >= 2), and the harness
// asserts the version it found rather than assuming it.
//
// Each fixture is compiled separately with `opa build -t wasm`, because
// OPA's wasm artifact *is* the policy -- there is no policy-independent
// OPA module to load. That asymmetry is the headline result, not a
// detail: zopa ships one ~62 KB module for every policy, OPA ships one
// module per policy and each is larger than zopa's whole engine.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const id = 'opa-wasm';
export const label = 'OPA (wasm, opa_eval)';

const ENTRYPOINT = 'authz/allow';

export async function available() {
  try {
    const out = execFileSync('opa', ['version'], { encoding: 'utf8' });
    const version = (out.match(/^Version:\s*(\S+)/m) ?? [])[1] ?? 'unknown';
    return { ok: true, note: `opa ${version}` };
  } catch {
    return { ok: false, reason: 'no `opa` on PATH' };
  }
}

// Fixtures without a `rego` field (the deep-nesting one, which has no
// readable Rego equivalent) are zopa-only by construction.
export function supports(fixture) {
  return typeof fixture.rego === 'string' && fixture.rego.length > 0;
}

// `opa build` is a build-time step, not a runtime one, so it is
// memoised: the cold-start measurement instantiates an already-compiled
// module, which is what a deployment does. Charging OPA for a compiler
// invocation it would never run in production would flatter zopa.
const compiled = new Map();

function compile(fixture) {
  const cached = compiled.get(fixture.rego);
  if (cached) return cached;
  const built = build(fixture);
  compiled.set(fixture.rego, built);
  return built;
}

function build(fixture) {
  const dir = mkdtempSync(join(tmpdir(), 'zopa-bench-opa-'));
  const rego = join(dir, 'policy.rego');
  writeFileSync(rego, fixture.rego);
  execFileSync(
    'opa',
    ['build', '-t', 'wasm', '-e', ENTRYPOINT, '-o', join(dir, 'bundle.tar.gz'), rego],
    { cwd: dir, stdio: 'pipe' },
  );
  execFileSync('tar', ['-xzf', 'bundle.tar.gz'], { cwd: dir, stdio: 'pipe' });
  const wasm = join(dir, 'policy.wasm');
  return { dir, wasm, bytes: readFileSync(wasm), size: statSync(wasm).size };
}

async function instantiate(bytes) {
  // Two pages is the minimum this module's memory import accepts, and
  // starting there rather than over-provisioning is what makes the
  // memory figure a measurement: whatever OPA needs beyond 128 KiB it
  // grows for itself, exactly as zopa's allocator does.
  const memory = new WebAssembly.Memory({ initial: 2 });
  const unexpected = (which) => () => {
    throw new Error(`opa-wasm: unexpected ${which} call; the fixture needs a builtin this harness does not provide`);
  };
  const { instance } = await WebAssembly.instantiate(bytes, {
    env: {
      memory,
      opa_abort: (addr) => { throw new Error(`opa-wasm: opa_abort at ${addr}`); },
      opa_println: () => 0,
      opa_builtin0: unexpected('opa_builtin0'),
      opa_builtin1: unexpected('opa_builtin1'),
      opa_builtin2: unexpected('opa_builtin2'),
      opa_builtin3: unexpected('opa_builtin3'),
      opa_builtin4: unexpected('opa_builtin4'),
    },
  });
  const e = instance.exports;
  const major = e.opa_wasm_abi_version?.value;
  const minor = e.opa_wasm_abi_minor_version?.value;
  if (major !== 1 || !(minor >= 2)) {
    throw new Error(`opa-wasm: ABI ${major}.${minor} does not export the opa_eval fast path this harness uses`);
  }
  return { e, memory };
}

export async function setup(fixture) {
  const built = compile(fixture);
  const { e, memory } = await instantiate(built.bytes);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const writeStr = (s) => {
    const bytes = enc.encode(s);
    const ptr = e.opa_malloc(bytes.length);
    if (ptr === 0) throw new Error('opa-wasm: opa_malloc failed');
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  };
  const readCStr = (ptr) => {
    const u8 = new Uint8Array(memory.buffer);
    let end = ptr;
    while (u8[end] !== 0) end++;
    return dec.decode(u8.subarray(ptr, end));
  };

  // Data is loaded once; the heap pointer captured afterwards is the
  // mark each evaluation rewinds to, which is how OPA's own SDK avoids
  // growing the heap per call.
  const [dataPtr, dataLen] = writeStr('{}');
  const dataAddr = e.opa_json_parse(dataPtr, dataLen);
  const baseHeap = e.opa_heap_ptr_get();

  let inputJson = JSON.stringify(fixture.input);

  return {
    // OPA answers with `[{"result": <value>}]`, or `[]` when the rule
    // is undefined. Undefined is a deny in every PEP that consumes it,
    // which is the same stance zopa takes, so both map onto zopa's
    // 1 / 0 / -1 for comparison.
    decide(nextInput) {
      if (nextInput !== undefined) inputJson = JSON.stringify(nextInput);
      e.opa_heap_ptr_set(baseHeap);
      const [inputPtr, inputLen] = writeStr(inputJson);
      const heapPtr = e.opa_heap_ptr_get();
      const resultAddr = e.opa_eval(0, 0, dataAddr, inputPtr, inputLen, heapPtr, 0);
      const parsed = JSON.parse(readCStr(resultAddr));
      if (parsed.length === 0) return 0;
      return parsed[0].result === true ? 1 : 0;
    },
    memoryBytes() {
      return memory.buffer.byteLength;
    },
    // Reported alongside latency because it is the number that makes
    // the size comparison concrete per policy.
    artifactBytes() {
      return built.size;
    },
    // The compiled artifact is shared across instantiations, so the
    // temp directory outlives any single engine instance and is cleaned
    // up by the OS rather than here.
    close() {},
  };
}
