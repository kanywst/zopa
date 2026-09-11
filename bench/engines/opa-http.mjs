// OPA as an out-of-process sidecar, queried over HTTP.
//
// This is the baseline zopa exists to replace, so the measurement
// deliberately includes the whole hop: JSON encode, loopback TCP,
// OPA's HTTP handler, decode. Subtracting the network to get a
// "fair" comparison would measure something nobody deploys.
//
// Loopback on the same machine is the *best* case for this shape. A
// real sidecar adds a container boundary, and a remote PDP adds a
// network. Read the number as a floor.

import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const id = 'opa-http';
export const label = 'OPA (HTTP sidecar)';
// `decide` awaits a network round trip, so the runner must time it with
// the async loop rather than the tight synchronous one.
export const isAsync = true;

const PATH_UNDER_DATA = 'authz/allow';
const READY_TIMEOUT_MS = 20_000;

export async function available() {
  try {
    execFileSync('opa', ['version'], { stdio: 'pipe' });
    return { ok: true };
  } catch {
    return { ok: false, reason: 'no `opa` on PATH' };
  }
}

export function supports(fixture) {
  return typeof fixture.rego === 'string' && fixture.rego.length > 0;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitReady(port, child) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`opa-http: server exited early with code ${child.exitCode}`);
    }
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) return;
    } catch {
      // not listening yet
    }
    await sleep(25);
  }
  throw new Error('opa-http: server did not become ready');
}

export async function setup(fixture) {
  const dir = mkdtempSync(join(tmpdir(), 'zopa-bench-opahttp-'));
  writeFileSync(join(dir, 'policy.rego'), fixture.rego);

  // Port 0 would be cleaner, but OPA does not report the bound port in
  // a machine-readable way, so pick one and let a collision surface as
  // the early-exit error above.
  const port = 18000 + Math.floor(Math.random() * 2000);
  const child = spawn(
    'opa',
    ['run', '--server', '--addr', `127.0.0.1:${port}`, '--log-level', 'error', 'policy.rego'],
    { cwd: dir, stdio: ['ignore', 'ignore', 'pipe'] },
  );
  let stderr = '';
  child.stderr.on('data', (b) => { stderr += b.toString(); });
  child.on('error', () => { /* surfaced via exitCode in waitReady */ });

  try {
    await waitReady(port, child);
  } catch (err) {
    child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`${err.message}${stderr ? `\n  opa stderr: ${stderr.trim()}` : ''}`);
  }

  const url = `http://127.0.0.1:${port}/v1/data/${PATH_UNDER_DATA}`;
  let body = JSON.stringify({ input: fixture.input });

  return {
    async decide(nextInput) {
      if (nextInput !== undefined) body = JSON.stringify({ input: nextInput });
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      });
      if (!res.ok) throw new Error(`opa-http: ${res.status} ${await res.text()}`);
      const json = await res.json();
      // A missing `result` key is OPA's undefined, same as the wasm
      // path's empty array: deny.
      if (!('result' in json)) return 0;
      return json.result === true ? 1 : 0;
    },
    // Read from OPA's own /metrics rather than from `ps`: it needs no
    // permission to inspect another process and it reports the same
    // number on every platform. `process_resident_memory_bytes` is the
    // RSS when the Go process collector is registered; otherwise
    // `go_memstats_sys_bytes` (total obtained from the OS) is the
    // closest portable stand-in.
    async memoryBytes() {
      try {
        const text = await (await fetch(`http://127.0.0.1:${port}/metrics`)).text();
        for (const key of ['process_resident_memory_bytes', 'go_memstats_sys_bytes']) {
          const hit = text.match(new RegExp(`^${key}\\s+(\\S+)`, 'm'));
          if (hit) return Number(hit[1]);
        }
        return null;
      } catch {
        return null;
      }
    },
    close() {
      child.kill('SIGTERM');
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
