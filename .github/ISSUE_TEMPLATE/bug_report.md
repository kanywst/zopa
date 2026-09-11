---
name: Bug report
about: Something isn't working
labels: bug
---

## Summary

What went wrong, in one sentence.

## Reproduction

Smallest input + AST + expected vs. actual decision. Paste the `evaluate(...)` return code or the HTTP status from your proxy.

```json
// input
```

```json
// AST
```

## Environment

- zopa version / commit:
- Zig version (`zig version`):
- Host runtime (Node / wasmtime / Envoy + version):
- OS / arch:

## Logs

If the issue is host-side (Envoy returning the wrong status, etc.), attach the relevant `proxy_log` lines or stderr.
