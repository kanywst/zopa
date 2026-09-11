# Response-side policies

Status: **Implemented.** Shipped in v0.2.0: `proxy_on_response_headers` evaluates `allow_response` against `{response: {status, headers}}`, and a deny sends a 503. The phase is gated on the rule existing, so a request-only policy passes responses through untouched. v0.3.0 added Envoy end-to-end coverage (`examples/envoy/envoy-phases.yaml`), which needed a loopback listener because a `direct_response` route is answered before the body is read. Kept for the reasoning; see `docs/proxy-wasm.md` for what actually shipped. Tracking: ROADMAP.md → Near term.

## Motivation

Today zopa only evaluates against the request side. `proxy_on_response_headers` is implemented as a no-op (`src/proxy_wasm.zig`). That means rules like "never let an upstream `5xx` reach the client", "block responses that leak `Server: <internal-build>`", or "redact responses for unauthenticated users" cannot be enforced.

Use cases:

- Cap `5xx` bleed during incidents (return a generic `503` instead).
- Strip / mask response headers that leak infra details.
- Force `Cache-Control: no-store` on routes the policy marks as sensitive.
- Enforce that responses to unauthenticated requests don't carry a `Set-Cookie`.

## Goals

1. Add a separate target rule: `allow_response` (or `deny_response`). Convention to be locked in §Open questions.
1. Implement `proxy_on_response_headers`:
   - Build an input shape reflecting response status and headers.
   - Evaluate the AST against the response target rule.
   - On deny, replace the response with a fixed status (see §Replacement contract for v1 behaviour and the deferred structured replacement).
   - On allow, fall through.
1. Reuse the existing AST machinery. No new node types are needed for v1; only a new target rule and a new input shape.

## Non-goals

- Response body inspection. Same pattern as request-body, but tracked with `body-aware-policies.md`. v1 only sees status + headers.
- Mutating the response in place. v1 either lets it through or replaces it entirely (status + body + headers from the rule's `value`).
- Per-route policy targeting. The same policy applies everywhere the filter is configured.

## Design sketch

### Per-context state

Eventually we want a per-context store that already holds request `:method` / `:path` so the response rule can reason about request → response pairs (sketched in `body-aware-policies.md`):

```zig
const ResponseContext = struct {
    request: *RequestContext,  // shared with request-side eval
    status: u32 = 0,
    headers: ?json.Value = null,
};
```

**v1 does not implement the snapshot.** The response rule sees only the response side. `input.request.*` becomes valid once the per-context plumbing lands; until then, body / response policies that need request context have to encode it via the host.

### Input shape

v1 (this PR) ships **only** the response subtree. The request-side `allow` rule keeps its existing flat shape (`input.method`, `input.path`, `input.headers`). They are disjoint inputs because they target disjoint rules.

```json
// allow_response input (this PR)
{
  "response": {
    "status":  500,
    "headers": { "server": "nginx/1.27", "...": "..." }
  }
}
```

The wider shape with both `input.request.*` and `input.response.*` visible together is the post-snapshot v2 picture and is not exposed yet:

```json
// v2 (deferred): both subtrees once the snapshot lands
{
  "request":  { "method": "GET", "path": "/admin/users", "headers": {} },
  "response": { "status": 500, "headers": {} }
}
```

### Replacement contract

**v1**: rule denies (returns `false` or `nil`) → zopa calls `proxy_send_local_response(503, ...)` with empty body / no extra headers. Allow falls through unchanged. The deny status code is **503** here (the upstream response is being replaced) vs **403** on the request-side `allow` path (the request is being rejected before it reaches upstream). The asymmetry is intentional.

**Deferred**: rule returns a structured value carrying status / body / headers, e.g.

```json
{
  "type": "value",
  "value": {
    "status":  503,
    "body":    "service temporarily unavailable",
    "headers": { "retry-after": "30" }
  }
}
```

This needs the evaluator to surface a `json.Value` (not a `bool`) to the proxy-wasm shim, plus a discriminator so the shim can tell "the policy returned a structured replacement" from "the policy returned a non-boolean truthy value (= allow)". Both changes are non-trivial and deferred to a follow-up PR.

## API impact

- New target rule name `allow_response` joins the existing `allow`.
- Existing `allow` policies continue to work unchanged: same input shape (`input.method` / `input.path` / `input.headers`), same return contract, same 403 deny status.
- v1 adds the `input.response.*` ref namespace under `allow_response`. `input.request.*` is reserved for v2 once per-context state lands.

## Test plan

- Node integration test: drive `evaluate` directly with a synthetic response-shaped input.
- Envoy integration test: extend `examples/envoy/run.sh` to assert a rewritten `503` when the upstream returns `500`.
- wasmtime test: walk through `proxy_on_request_headers` → `proxy_on_response_headers` and verify the request snapshot is still reachable from the response rule.

## Open questions

- Naming: `allow_response` (additive) vs `deny_response` (subtractive)? Picking the wrong default biases policies; revisit before implementation.
- Should the request snapshot be auto-cleared after the response phase, or kept until `proxy_on_done`? Memory vs late-binding tradeoff.
- How should the `value` shape diverge from a plain boolean? If we ever want partial mutation (just a header swap, not a full replacement) the schema needs a `mode` discriminator.
