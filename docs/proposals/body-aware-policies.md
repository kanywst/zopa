# Body-aware policies

Status: **Implemented.** The body phase shipped in v0.2.0 — `proxy_on_request_body` evaluates `allow_body` against `{body, body_raw}` once the host signals end of stream, with a 64 KiB buffer cap — and was hardened in v0.3.0: non-final chunks return `StopIterationAndBuffer` so the host accumulates rather than forwarding fragments, `body_truncated` joins the input, and a body over the cap denies whenever the policy reads it. Kept for the reasoning; see `docs/proxy-wasm.md` for what actually shipped.
Tracking: ROADMAP.md → Near term.

## Motivation

Today zopa decides allow/deny purely from request headers. That covers
authn-style checks ("Authorization must match a SPIFFE pattern",
"method must be GET"), but it can't reason about the body.

Use cases that need body access:

- Reject requests where a JSON body field falls outside a numeric range
  (`input.body.amount > 10000` → deny).
- Block form posts that lack a CSRF nonce field.
- Refuse requests whose body matches a deny-listed substring (cheap WAF).

Currently `proxy_on_request_body` is a no-op (`src/proxy_wasm.zig`)
because by the time it fires, the request pseudo-headers (`:method`,
`:path`, `:authority`) have already been cleared from the header map.
A rule that references both `input.method` and `input.body.amount`
cannot be evaluated in either callback alone.

## Goals

1. Implement `proxy_on_request_body`:
   - Wait for `end_of_stream` (or buffer up to `max_body_bytes`).
   - Read the body via `proxy_get_buffer_bytes(BufferType.HttpRequestBody)`.
   - Build an `input` JSON containing the parsed body.
   - Evaluate the AST against a separate target rule `allow_body`.
   - On deny, call `proxy_send_local_response(403)` and return Pause;
     on allow, return Continue.

### v1 vs v2

**v1 (this PR)**: body callback always runs against `allow_body`
when it fires, with body-only input (no request snapshot, no
opt-in flag, no per-prefix optimization). Header-side `allow` keeps
its existing flat input untouched.

**v2 (deferred)**:

- Per-context snapshot of `:method` / `:path` / `:authority` /
  selected headers in `proxy_on_request_headers`, surfaced to the
  body rule as `input.method` etc.
- Opt-in plugin config flag `require_body_eval: true` so hosts
  that don't need body inspection skip buffering. When the flag
  is on, the header phase still evaluates `allow` and short-circuits
  on header-only deny decisions before the body fires (saves CPU
  and the buffering cost on rejected requests).
- Static AST analysis (see `streaming-evaluation.md`) can flip the
  flag automatically when the policy references `input.body.*`.

## Non-goals

- Streaming evaluation (tracked separately in
  `streaming-evaluation.md`). v1 buffers up to `max_body_bytes`.
- Mutating the body. zopa stays decision-only.
- Binary body parsers (protobuf, msgpack). v1 is JSON-only via
  `src/json.zig`. Other shapes get the raw byte slice as
  `input.body_raw`.

## Design sketch

### Per-context state (v2 only)

The v2 snapshot would look like:

```zig
const RequestContext = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    headers: ?json.Value = null,
};
```

with a `AutoHashMap(u32, *RequestContext)` keyed by `context_id`. The
naive design holds the map in `host_allocator`, which means every
field carries a manual `defer free` and `proxy_on_done` has to deep-
free the inner string slices and the parsed `json.Value` tree.

A cleaner approach (recommended, captured here so v2 starts from the
right shape): give each context its **own arena**, allocated lazily
on the first header callback and reset / freed in `proxy_on_done`.
Saves the per-field free dance.

**v1 has no per-context state.** Header / body callbacks operate
independently and the body rule only sees the body itself.

### Input shape

v1 (this PR) — body-only:

```json
{
  "body":     { "amount": 250 },
  "body_raw": "{\"amount\":250}"
}
```

v2 (deferred) — body plus the request snapshot:

```json
{
  "method":  "POST",
  "path":    "/orders",
  "headers": { "...": "..." },
  "body":     { "amount": 250 },
  "body_raw": "{\"amount\":250}"
}
```

`body` is set to JSON `null` (not `undefined` -- that is not a JSON
value) when the body fails to parse as JSON, when the body is empty,
or when the read was truncated by `max_body_bytes`. In every case
`body_raw` carries whatever bytes the host returned (capped). Rego-
style policies that want to distinguish "no body" from "non-JSON
body" can branch on `body_raw == ""` vs `body == null`.

### Buffer limit

v1 hardcodes `max_body_bytes = 64 * 1024`. v2 will lift this into
the plugin config alongside `require_body_eval`. When the host
returns more than the cap, `proxy_get_buffer_bytes(start=0, max=cap)`
already truncates on the host side -- v1 does not re-truncate, so
`body_raw` length is always `<= cap` and `body` is `null` whenever
the truncated bytes do not parse as a complete JSON document.

## API impact

- `proxy_on_request_body` returns `Action.Pause` on deny only (sends
  403 first via `proxy_send_local_response`). Allow returns Continue.
- New target rule name `allow_body` joins `allow` and `allow_response`.
- New AST refs become valid under `allow_body`: `input.body.<path>`,
  `input.body_raw`.
- Existing `allow` policies continue to work unchanged (request-side
  input shape stays flat with `input.method` / `input.path` /
  `input.headers`).

## Test plan

- Node integration test: drive `evaluate` with a synthetic input that
  includes `body`, verify `ref` resolves into the body subtree.
- Envoy integration test: extend `examples/envoy/run.sh` with a POST
  case that depends on a body field.
- wasmtime test: simulate `proxy_on_request_headers` then
  `proxy_on_request_body`, check the snapshot survives between
  callbacks.

## Open questions

- How to surface non-JSON bodies (`application/x-www-form-urlencoded`,
  binary protocols)? Either a small parser in `src/json.zig` or push
  the burden to the host through a richer input ABI.
- Right default for `max_body_bytes`? 64 KiB feels small for GraphQL,
  large for control-plane chatter.
- Should `require_body_eval` be inferred from the policy AST (does it
  reference `input.body`)? Static AST analysis would flip the flag
  ergonomically.
