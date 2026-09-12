// zopa with the policy built once and held, via `policy_compile` +
// `evaluate_compiled`.
//
// This is the arrangement the proxy-wasm shim has always used
// internally -- `proxy_on_configure` builds the policy onto a
// long-lived arena and every callback evaluates against it -- exposed
// so a plain `WebAssembly.Module` host can do the same. Per decision
// the work is the input parse plus the rule walk; no policy parse, no
// AST construction.
//
// Sitting next to the `zopa` row, the difference between the two is a
// direct measurement of what the AST parse costs on each fixture.

import { readFileSync, statSync } from 'node:fs';

export const id = 'zopa-compiled';
export const label = 'zopa (compiled policy)';

const hostStubs = {
  proxy_log: () => 0,
  proxy_get_buffer_bytes: () => 1,
  proxy_get_header_map_pairs: () => 1,
  proxy_get_header_map_value: () => 1,
  proxy_send_local_response: () => 0,
};

export async function available({ wasmPath }) {
  try {
    const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), { env: hostStubs });
    if (typeof instance.exports.policy_compile !== 'function') {
      return { ok: false, reason: `${wasmPath} has no policy_compile export (build predates it)` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `${wasmPath}: ${err.code ?? err.message}` };
  }
}

export function supports() {
  return true;
}

export async function setup(fixture, { wasmPath }) {
  const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), { env: hostStubs });
  const {
    malloc, free, memory,
    policy_compile, policy_release, evaluate_compiled,
  } = instance.exports;
  const enc = new TextEncoder();

  const write = (obj) => {
    const bytes = enc.encode(JSON.stringify(obj));
    const ptr = malloc(bytes.length);
    if (ptr === 0) throw new Error('zopa-compiled: malloc failed');
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return { ptr, len: bytes.length };
  };

  // Compile once, outside the measurement, and free the AST bytes
  // immediately: the module copied what it needs onto the policy's own
  // arena, and a host that kept them alive would be holding the policy
  // twice.
  const astBuf = write(fixture.ast);
  const handle = policy_compile(astBuf.ptr, astBuf.len);
  free(astBuf.ptr);
  if (handle <= 0) throw new Error(`zopa-compiled: policy_compile rejected ${fixture.name}`);

  let input = write(fixture.input);

  return {
    decide(nextInput) {
      if (nextInput !== undefined) {
        free(input.ptr);
        input = write(nextInput);
      }
      return evaluate_compiled(handle, input.ptr, input.len);
    },
    memoryBytes() {
      return memory.buffer.byteLength;
    },
    artifactBytes() {
      return statSync(wasmPath).size;
    },
    close() {
      free(input.ptr);
      policy_release(handle);
    },
  };
}
