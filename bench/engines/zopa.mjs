// zopa, in both of its generic-ABI shapes.
//
// `zopa` drives `evaluate(input, ast)`, which is handed the policy on
// every call and so pays a parse and an AST build per decision. That is
// an upper bound on the per-request cost, not an estimate of it.
//
// `zopa-compiled` drives `policy_compile` once and then
// `evaluate_compiled(handle, input)`, which is the arrangement
// proxy-wasm has always used internally: parse the input, walk the
// rules, nothing else. Both are measured because the gap between them
// is the interesting number -- it is exactly what the AST parse costs,
// and it is why the one-shot path loses to OPA's wasm build on the RBAC
// fixture.

import { readFileSync, statSync } from 'node:fs';

export const id = 'zopa';
export const label = 'zopa (evaluate)';

// The generic ABI never calls these. They exist so a drifted build that
// *does* reach a host call fails loudly instead of trapping on a
// missing import.
const hostStubs = {
  proxy_log: () => 0,
  proxy_get_buffer_bytes: () => 1,
  proxy_get_header_map_pairs: () => 1,
  proxy_get_header_map_value: () => 1,
  proxy_send_local_response: () => 0,
};

export async function available({ wasmPath }) {
  try {
    readFileSync(wasmPath);
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `${wasmPath}: ${err.code ?? err.message}` };
  }
}

// Every fixture carries a zopa AST, so there is nothing to compile.
export function supports() {
  return true;
}

export async function setup(fixture, { wasmPath }) {
  const { instance } = await WebAssembly.instantiate(
    readFileSync(wasmPath),
    { env: hostStubs },
  );
  const { malloc, free, evaluate, memory } = instance.exports;
  const enc = new TextEncoder();

  const write = (obj) => {
    const bytes = enc.encode(JSON.stringify(obj));
    const ptr = malloc(bytes.length);
    if (ptr === 0) throw new Error('zopa: malloc failed');
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };

  // The AST buffer is written once and reused across iterations, which
  // is what a host driving the same policy repeatedly would do.
  const ast = write(fixture.ast);
  let input = write(fixture.input);

  return {
    decide(nextInput) {
      if (nextInput !== undefined) {
        free(input.ptr);
        input = write(nextInput);
      }
      return evaluate(input.ptr, input.len, ast.ptr, ast.len);
    },
    memoryBytes() {
      return memory.buffer.byteLength;
    },
    // One module serves every policy, so this number is the same on
    // every row -- which is the comparison worth drawing against OPA's
    // per-policy artifact.
    artifactBytes() {
      return statSync(wasmPath).size;
    },
    close() {
      free(input.ptr);
      free(ast.ptr);
    },
  };
}
