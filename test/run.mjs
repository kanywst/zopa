// Integration tests for zopa.wasm via the generic `evaluate` export.
// proxy-wasm imports are stubbed because the test path doesn't reach
// them; a stub firing means the harness has drifted.
//
//   node test/run.mjs                # uses zig-out/bin/zopa.wasm
//   node test/run.mjs path/to.wasm   # explicit path

import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';

const wasmPath = argv[2] ?? 'zig-out/bin/zopa.wasm';
const bytes = readFileSync(wasmPath);

const { instance } = await WebAssembly.instantiate(bytes, {
  env: {
    proxy_log: () => 0,
    proxy_get_buffer_bytes: () => 1,
    proxy_get_header_map_pairs: () => 1,
    proxy_get_header_map_value: () => 1,
    proxy_send_local_response: () => 0,
  },
});

const { malloc, free, evaluate, evaluate_target, memory } = instance.exports;
const enc = new TextEncoder();

function writeBytes(bytes) {
  const ptr = malloc(bytes.length);
  if (ptr === 0) throw new Error('malloc failed');
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function writeJson(obj) {
  return writeBytes(enc.encode(JSON.stringify(obj)));
}

function freeBuf({ ptr }) {
  free(ptr);
}

function decide(input, ast) {
  const i = writeJson(input);
  const a = writeJson(ast);
  try {
    return evaluate(i.ptr, i.len, a.ptr, a.len);
  } finally {
    freeBuf(i);
    freeBuf(a);
  }
}

function decideTarget(input, ast, target) {
  const i = writeJson(input);
  const a = writeJson(ast);
  const t = writeBytes(enc.encode(target));
  try {
    return evaluate_target(i.ptr, i.len, a.ptr, a.len, t.ptr, t.len);
  } finally {
    freeBuf(i);
    freeBuf(a);
    freeBuf(t);
  }
}

let failed = 0;
function check(name, got, expected) {
  if (got === expected) {
    console.log(`PASS  ${name}`);
  } else {
    console.log(`FAIL  ${name}: got ${got}, expected ${expected}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// 1. legacy bare expression -- a literal `true` is wrapped into a
//    synthetic `allow` rule with body `[true]` and yields allow.
// ---------------------------------------------------------------------------
check(
  'bare literal true -> allow',
  decide({}, { type: 'value', value: true }),
  1,
);

check(
  'bare literal false -> deny',
  decide({}, { type: 'value', value: false }),
  0,
);

// ---------------------------------------------------------------------------
// 2. compare ops
// ---------------------------------------------------------------------------
const refRole = { type: 'ref', path: ['input', 'user', 'role'] };

check(
  'compare eq -> allow',
  decide(
    { user: { role: 'admin' } },
    { type: 'compare', op: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
  ),
  1,
);

check(
  'compare eq -> deny on mismatch',
  decide(
    { user: { role: 'guest' } },
    { type: 'compare', op: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
  ),
  0,
);

check(
  'compare neq -> allow on mismatch',
  decide(
    { user: { role: 'guest' } },
    { type: 'compare', op: 'neq', left: refRole, right: { type: 'value', value: 'admin' } },
  ),
  1,
);

const refAge = { type: 'ref', path: ['input', 'age'] };
check(
  'compare lt -> allow',
  decide({ age: 17 }, { type: 'compare', op: 'lt', left: refAge, right: { type: 'value', value: 18 } }),
  1,
);
check(
  'compare lte -> allow at boundary',
  decide({ age: 18 }, { type: 'compare', op: 'lte', left: refAge, right: { type: 'value', value: 18 } }),
  1,
);
check(
  'compare gt -> deny at boundary',
  decide({ age: 18 }, { type: 'compare', op: 'gt', left: refAge, right: { type: 'value', value: 18 } }),
  0,
);
check(
  'compare gte -> allow at boundary',
  decide({ age: 18 }, { type: 'compare', op: 'gte', left: refAge, right: { type: 'value', value: 18 } }),
  1,
);

// ---------------------------------------------------------------------------
// 3. shorthand `{type:"eq", ...}` aliasing
// ---------------------------------------------------------------------------
check(
  'eq shorthand -> allow',
  decide(
    { user: { role: 'admin' } },
    { type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
  ),
  1,
);

// ---------------------------------------------------------------------------
// 4. not
// ---------------------------------------------------------------------------
check(
  'not flips false to allow',
  decide(
    { admin: false },
    { type: 'not', expr: { type: 'ref', path: ['input', 'admin'] } },
  ),
  1,
);
check(
  'not flips true to deny',
  decide(
    { admin: true },
    { type: 'not', expr: { type: 'ref', path: ['input', 'admin'] } },
  ),
  0,
);

// ---------------------------------------------------------------------------
// 5. module with default rule
// ---------------------------------------------------------------------------
const adminPolicy = {
  type: 'module',
  rules: [
    {
      type: 'rule',
      name: 'allow',
      default: true,
      value: { type: 'value', value: false },
    },
    {
      type: 'rule',
      name: 'allow',
      body: [
        { type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
      ],
    },
  ],
};
check('module default deny when not admin', decide({ user: { role: 'guest' } }, adminPolicy), 0);
check('module rule fires when admin', decide({ user: { role: 'admin' } }, adminPolicy), 1);

// ---------------------------------------------------------------------------
// 6. nested compare in rule.value
// ---------------------------------------------------------------------------
const ageGate = {
  type: 'module',
  rules: [
    {
      type: 'rule',
      name: 'allow',
      body: [{ type: 'value', value: true }],
      value: { type: 'compare', op: 'gte', left: refAge, right: { type: 'value', value: 18 } },
    },
  ],
};
check('nested compare in value: 25 >= 18 -> allow', decide({ age: 25 }, ageGate), 1);
check('nested compare in value: 12 >= 18 -> deny', decide({ age: 12 }, ageGate), 0);

// ---------------------------------------------------------------------------
// 7. set-style equality (set literal == set value via ref-of-set is
//    not supported yet; here we verify that the set literal builder
//    parses without error and equals itself when wrapped in a body).
// ---------------------------------------------------------------------------
check(
  'set literal in body: definedness -> allow',
  decide(
    {},
    {
      type: 'module',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [{ type: 'set', items: ['a', 'b', 'c'] }],
        },
      ],
    },
  ),
  1,
);

// ---------------------------------------------------------------------------
// 8. invalid input JSON -> -1
// ---------------------------------------------------------------------------
{
  const badBytes = enc.encode('{bad}');
  const bad = writeBytes(badBytes);
  const a = writeJson({ type: 'value', value: true });
  const r = evaluate(bad.ptr, bad.len, a.ptr, a.len);
  freeBuf(bad);
  freeBuf(a);
  check('invalid input json -> -1', r, -1);
}

// ---------------------------------------------------------------------------
// 9. surrogate pair round-trip through 𝄞
// ---------------------------------------------------------------------------
{
  // Emit the AST literal as JSON containing the surrogate pair
  // escape, parsed by zopa as U+1D11E.
  const inputBytes = enc.encode(JSON.stringify({ name: '\u{1D11E}' }));
  const astText = '{"type":"compare","op":"eq",'
    + '"left":{"type":"ref","path":["input","name"]},'
    + '"right":{"type":"value","value":"\\uD834\\uDD1E"}}';
  const i = writeBytes(inputBytes);
  const a = writeBytes(enc.encode(astText));
  const r = evaluate(i.ptr, i.len, a.ptr, a.len);
  freeBuf(i);
  freeBuf(a);
  check('surrogate-pair literal equals U+1D11E in input', r, 1);
}

// ---------------------------------------------------------------------------
// 10. eval depth guard: deeply nested `not` should error out, not
//     stack-overflow. The evaluator collapses the nesting to bool, so
//     we wrap a literal in 64 `not`s -- one over the depth limit.
// ---------------------------------------------------------------------------
{
  let nested = { type: 'value', value: true };
  for (let i = 0; i < 64; i++) {
    nested = { type: 'not', expr: nested };
  }
  // Beyond the depth cap -> error path -> -1.
  check('64 nested nots trip depth guard -> -1', decide({}, nested), -1);
}

// ---------------------------------------------------------------------------
// 11. legacy ref-as-decision: ref to a missing path is undefined
//     and our evaluator denies.
// ---------------------------------------------------------------------------
check(
  'missing ref -> deny',
  decide({}, { type: 'ref', path: ['input', 'missing'] }),
  0,
);

// ---------------------------------------------------------------------------
// 12. some / every iterators
// ---------------------------------------------------------------------------
const someAdmin = {
  type: 'some',
  var: 'tag',
  source: { type: 'ref', path: ['input', 'tags'] },
  body: {
    type: 'eq',
    left: { type: 'ref', path: ['tag'] },
    right: { type: 'value', value: 'admin' },
  },
};
check('some: matching element -> allow', decide({ tags: ['viewer', 'admin', 'guest'] }, someAdmin), 1);
check('some: no match -> deny', decide({ tags: ['viewer', 'guest'] }, someAdmin), 0);
check('some: empty source -> deny', decide({ tags: [] }, someAdmin), 0);

const everyAdmin = {
  type: 'every',
  var: 'tag',
  source: { type: 'ref', path: ['input', 'tags'] },
  body: {
    type: 'eq',
    left: { type: 'ref', path: ['tag'] },
    right: { type: 'value', value: 'admin' },
  },
};
check('every: all match -> allow', decide({ tags: ['admin', 'admin'] }, everyAdmin), 1);
check('every: one mismatch -> deny', decide({ tags: ['admin', 'guest'] }, everyAdmin), 0);
check('every: vacuously true on empty -> allow', decide({ tags: [] }, everyAdmin), 1);

// some over a set literal in the AST
const someInLiteralSet = {
  type: 'some',
  var: 'role',
  source: { type: 'set', items: ['admin', 'editor'] },
  body: {
    type: 'eq',
    left: { type: 'ref', path: ['role'] },
    right: { type: 'ref', path: ['input', 'user', 'role'] },
  },
};
check('some: literal set membership -> allow', decide({ user: { role: 'editor' } }, someInLiteralSet), 1);
check('some: literal set non-member -> deny', decide({ user: { role: 'viewer' } }, someInLiteralSet), 0);

// nested some inside an `every` -- each pair (perm, allowed) checks
// that every required permission is in the user's grants set.
const userHasAllRequired = {
  type: 'every',
  var: 'required',
  source: { type: 'ref', path: ['input', 'required_perms'] },
  body: {
    type: 'some',
    var: 'granted',
    source: { type: 'ref', path: ['input', 'user', 'perms'] },
    body: {
      type: 'eq',
      left: { type: 'ref', path: ['granted'] },
      right: { type: 'ref', path: ['required'] },
    },
  },
};
check(
  'every+some: user has every required perm -> allow',
  decide({ required_perms: ['read', 'write'], user: { perms: ['read', 'write', 'admin'] } }, userHasAllRequired),
  1,
);
check(
  'every+some: missing one required perm -> deny',
  decide({ required_perms: ['read', 'delete'], user: { perms: ['read', 'write'] } }, userHasAllRequired),
  0,
);

// ---------------------------------------------------------------------------
// 8. call: builtin functions (startswith / endswith / contains / count)
// ---------------------------------------------------------------------------
const callStartswith = (path, prefix) => ({
  type: 'call', name: 'startswith',
  args: [
    { type: 'ref', path: ['input', 'path'] },
    { type: 'value', value: prefix },
  ],
});
check('call startswith on input.path -> allow', decide({ path: '/admin/users' }, callStartswith('path', '/admin/')), 1);
check('call startswith on input.path -> deny',  decide({ path: '/users' },        callStartswith('path', '/admin/')), 0);

check(
  'call endswith on host -> allow',
  decide({ host: 'api.internal' }, {
    type: 'call', name: 'endswith',
    args: [
      { type: 'ref', path: ['input', 'host'] },
      { type: 'value', value: '.internal' },
    ],
  }),
  1,
);

check(
  'call contains in user-agent -> allow',
  decide({ ua: 'Mozilla/5.0 Bot' }, {
    type: 'call', name: 'contains',
    args: [
      { type: 'ref', path: ['input', 'ua'] },
      { type: 'value', value: 'Bot' },
    ],
  }),
  1,
);

// count compared to a literal, used in body position.
check(
  'call count > 2 over array -> allow',
  decide({ perms: ['r', 'w', 'x'] }, {
    type: 'gt',
    left: { type: 'call', name: 'count', args: [{ type: 'ref', path: ['input', 'perms'] }] },
    right: { type: 'value', value: 2 },
  }),
  1,
);
check(
  'call count > 2 over array -> deny',
  decide({ perms: ['r'] }, {
    type: 'gt',
    left: { type: 'call', name: 'count', args: [{ type: 'ref', path: ['input', 'perms'] }] },
    right: { type: 'value', value: 2 },
  }),
  0,
);

// unknown builtin: lookup miss resolves to .nil, treated as falsy in
// body position -> the synthetic `allow` rule fails -> deny (0). The
// proxy-wasm shim treats any non-1 the same way (deny).
check(
  'call unknown builtin -> deny',
  decide({}, {
    type: 'call', name: 'made_up_function',
    args: [{ type: 'value', value: 1 }],
  }),
  0,
);

// ---------------------------------------------------------------------------
// 9. some / every over object refs (kind: keys / values, default keys)
// ---------------------------------------------------------------------------
const everyKeyNotInternal = {
  type: 'every', var: 'k', kind: 'keys',
  source: { type: 'ref', path: ['input', 'attrs'] },
  body: {
    type: 'neq',
    left: { type: 'ref', path: ['k'] },
    right: { type: 'value', value: 'internal' },
  },
};
check(
  'every over object keys: no banned key -> allow',
  decide({ attrs: { team: 'sre', region: 'us-east' } }, everyKeyNotInternal),
  1,
);
check(
  'every over object keys: banned key present -> deny',
  decide({ attrs: { team: 'sre', internal: 'yes' } }, everyKeyNotInternal),
  0,
);

const someValueTrue = {
  type: 'some', var: 'v', kind: 'values',
  source: { type: 'ref', path: ['input', 'flags'] },
  body: {
    type: 'eq',
    left: { type: 'ref', path: ['v'] },
    right: { type: 'value', value: true },
  },
};
check(
  'some over object values: at least one true -> allow',
  decide({ flags: { a: false, b: true, c: false } }, someValueTrue),
  1,
);
check(
  'some over object values: all false -> deny',
  decide({ flags: { a: false, b: false } }, someValueTrue),
  0,
);

// `kind` defaults to "keys" when omitted on an object source.
const everyDefaultKeysNotBanned = {
  type: 'every', var: 'k',
  source: { type: 'ref', path: ['input', 'm'] },
  body: {
    type: 'neq',
    left: { type: 'ref', path: ['k'] },
    right: { type: 'value', value: 'banned' },
  },
};
check(
  'every over object defaults to keys: clean -> allow',
  decide({ m: { x: 1, y: 2 } }, everyDefaultKeysNotBanned),
  1,
);
check(
  'every over object defaults to keys: banned -> deny',
  decide({ m: { x: 1, banned: 2 } }, everyDefaultKeysNotBanned),
  0,
);

// ---------------------------------------------------------------------------
// 10. modules bundle: package addressing
//
// The default `evaluate` ABI targets package="" + rule="allow", so a
// bare module wrapped at the top level keeps working. A modules
// bundle with package="" still answers via the default entry point.
// (Cross-package addressing is exercised by zig build test-unit.)
// ---------------------------------------------------------------------------
const wrappedModule = {
  type: 'modules',
  modules: [
    {
      type: 'module',
      package: '',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [
            { type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
          ],
        },
      ],
    },
  ],
};
check('modules bundle: empty package -> allow when admin',  decide({ user: { role: 'admin' } },  wrappedModule), 1);
check('modules bundle: empty package -> deny when guest',   decide({ user: { role: 'guest' } },  wrappedModule), 0);

// Bundle with two packages: the default ABI only sees the empty-package
// module. The "audit" module is invisible from the default entry.
const twoPackages = {
  type: 'modules',
  modules: [
    {
      type: 'module',
      package: '',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [
            { type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } },
          ],
        },
      ],
    },
    {
      type: 'module',
      package: 'audit',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [{ type: 'value', value: true }],
        },
      ],
    },
  ],
};
check('modules bundle: default entry picks empty package', decide({ user: { role: 'admin' } }, twoPackages), 1);
check('modules bundle: audit module invisible from default entry', decide({ user: { role: 'guest' } }, twoPackages), 0);

// ---------------------------------------------------------------------------
// 11. evaluate_target: response-side rules driven via the new export.
//
// proxy_on_response_headers in proxy_wasm.zig fires the
// "allow_response" target rule against an input shape with response
// status / headers. The generic `evaluate_target` export lets hosts
// reach the same eval path without going through proxy-wasm.
// ---------------------------------------------------------------------------
const responsePolicy = {
  type: 'module',
  rules: [
    { type: 'rule', name: 'allow_response', default: true, value: { type: 'value', value: true } },
    {
      type: 'rule',
      name: 'allow_response',
      body: [
        {
          type: 'gte',
          left: { type: 'ref', path: ['input', 'response', 'status'] },
          right: { type: 'value', value: 500 },
        },
      ],
      value: { type: 'value', value: false },
    },
  ],
};
check(
  'evaluate_target allow_response: 500 -> deny (replace with 503)',
  decideTarget({ response: { status: 500, headers: {} } }, responsePolicy, 'allow_response'),
  0,
);
check(
  'evaluate_target allow_response: 200 -> allow',
  decideTarget({ response: { status: 200, headers: {} } }, responsePolicy, 'allow_response'),
  1,
);
check(
  'evaluate_target with missing target rule -> deny',
  decideTarget({}, { type: 'value', value: true }, 'allow_response'),
  0,
);

// ---------------------------------------------------------------------------
// 12. evaluate_target: body-side rules driven via the new export.
//
// proxy_on_request_body in proxy_wasm.zig fires the "allow_body"
// target rule against {body, body_raw}. The generic evaluate_target
// export lets hosts reach the same eval path without proxy-wasm.
// ---------------------------------------------------------------------------
const bodyPolicy = {
  type: 'module',
  rules: [
    { type: 'rule', name: 'allow_body', default: true, value: { type: 'value', value: true } },
    {
      type: 'rule',
      name: 'allow_body',
      body: [
        {
          type: 'gt',
          left: { type: 'ref', path: ['input', 'body', 'amount'] },
          right: { type: 'value', value: 1000 },
        },
      ],
      value: { type: 'value', value: false },
    },
  ],
};
check(
  'evaluate_target allow_body: amount over limit -> deny',
  decideTarget({ body: { amount: 5000 }, body_raw: '{"amount":5000}' }, bodyPolicy, 'allow_body'),
  0,
);
check(
  'evaluate_target allow_body: amount under limit -> allow',
  decideTarget({ body: { amount: 50 }, body_raw: '{"amount":50}' }, bodyPolicy, 'allow_body'),
  1,
);

// body_raw fallback: policies can match on the raw bytes when the
// body did not parse as JSON.
const rawPolicy = {
  type: 'module',
  rules: [
    {
      type: 'rule',
      name: 'allow_body',
      body: [
        {
          type: 'eq',
          left: { type: 'ref', path: ['input', 'body_raw'] },
          right: { type: 'value', value: 'BLOCKED' },
        },
      ],
      value: { type: 'value', value: false },
    },
    { type: 'rule', name: 'allow_body', default: true, value: { type: 'value', value: true } },
  ],
};
check(
  'evaluate_target allow_body: body_raw=BLOCKED -> deny',
  decideTarget({ body: null, body_raw: 'BLOCKED' }, rawPolicy, 'allow_body'),
  0,
);
check(
  'evaluate_target allow_body: body_raw=ok -> allow',
  decideTarget({ body: null, body_raw: 'ok' }, rawPolicy, 'allow_body'),
  1,
);

// ---------------------------------------------------------------------------
// 14. evaluate_addressed: dispatch by (package, rule). The other
//     suites reach packages only through the implicit `""` default, so
//     this export was shipped without a single host-side caller.
// ---------------------------------------------------------------------------
const { evaluate_addressed } = instance.exports;

function decideAddressed(input, ast, pkg, target) {
  const i = writeJson(input);
  const a = writeJson(ast);
  const p = writeBytes(enc.encode(pkg));
  const t = writeBytes(enc.encode(target));
  try {
    return evaluate_addressed(i.ptr, i.len, a.ptr, a.len, p.ptr, p.len, t.ptr, t.len);
  } finally {
    freeBuf(i);
    freeBuf(a);
    freeBuf(p);
    freeBuf(t);
  }
}

const addressedPackages = {
  type: "modules",
  modules: [
    {
      type: "module",
      package: "authz",
      rules: [
        {
          type: "rule",
          name: "allow",
          body: [{ type: "eq", left: refRole, right: { type: "value", value: "admin" } }],
        },
      ],
    },
    {
      type: "module",
      package: "audit",
      rules: [{ type: "rule", name: "allow", body: [{ type: "value", value: true }] }],
    },
  ],
};

check(
  'addressed: authz.allow fires for admin',
  decideAddressed({ user: { role: 'admin' } }, addressedPackages, 'authz', 'allow'),
  1,
);
check(
  'addressed: authz.allow denies a guest',
  decideAddressed({ user: { role: 'guest' } }, addressedPackages, 'authz', 'allow'),
  0,
);
check(
  'addressed: audit.allow fires regardless of role',
  decideAddressed({ user: { role: 'guest' } }, addressedPackages, 'audit', 'allow'),
  1,
);
check(
  'addressed: unknown package denies',
  decideAddressed({ user: { role: 'admin' } }, addressedPackages, 'nope', 'allow'),
  0,
);
check(
  'addressed: unknown rule denies',
  decideAddressed({ user: { role: 'admin' } }, addressedPackages, 'authz', 'allow_body'),
  0,
);

// ---------------------------------------------------------------------------
// 15. A package split across modules is one rule set: the `default`
//     declared in one module governs rules declared in another, and a
//     later module's explicit deny is not skipped by an earlier match.
// ---------------------------------------------------------------------------
const splitPackage = {
  type: 'modules',
  modules: [
    {
      type: 'module',
      package: 'authz',
      rules: [{ type: 'rule', name: 'allow', default: true, value: { type: 'value', value: true } }],
    },
    {
      type: 'module',
      package: 'authz',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [{ type: 'eq', left: refRole, right: { type: 'value', value: 'banned' } }],
          value: { type: 'value', value: false },
        },
      ],
    },
  ],
};

check(
  'split package: sibling module inherits the default -> allow',
  decideAddressed({ user: { role: 'viewer' } }, splitPackage, 'authz', 'allow'),
  1,
);
check(
  'split package: deny rule in the second module still fires',
  decideAddressed({ user: { role: 'banned' } }, splitPackage, 'authz', 'allow'),
  0,
);

// Two definitions of the same complete rule that hold at once with
// different values ask for two outputs. OPA reports that as
// eval_conflict_error; zopa returns -1, which every caller denies on.
// Resolving it by bundle order instead would make the answer depend on
// which file a rule happens to live in.
const conflicting = {
  type: 'modules',
  modules: [
    {
      type: 'module',
      package: 'authz',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [{ type: 'eq', left: { type: 'ref', path: ['input', 'tenant'] }, right: { type: 'value', value: 'acme' } }],
        },
      ],
    },
    {
      type: 'module',
      package: 'authz',
      rules: [
        {
          type: 'rule',
          name: 'allow',
          body: [{ type: 'eq', left: refRole, right: { type: 'value', value: 'banned' } }],
          value: { type: 'value', value: false },
        },
      ],
    },
  ],
};

check(
  'conflicting definitions -> -1 (deny), not first-in-bundle',
  decideAddressed({ tenant: 'acme', user: { role: 'banned' } }, conflicting, 'authz', 'allow'),
  -1,
);
check(
  'only the allow definition holds -> allow',
  decideAddressed({ tenant: 'acme', user: { role: 'viewer' } }, conflicting, 'authz', 'allow'),
  1,
);
check(
  'only the deny definition holds -> deny',
  decideAddressed({ tenant: 'other', user: { role: 'banned' } }, conflicting, 'authz', 'allow'),
  0,
);
// Two `default` declarations for one rule: rego_type_error in OPA,
// rejected when the AST is built here.
check(
  'two defaults for one rule -> -1',
  decideAddressed(
    {},
    {
      type: 'modules',
      modules: [
        {
          type: 'module',
          package: 'authz',
          rules: [{ type: 'rule', name: 'allow', default: true, value: { type: 'value', value: false } }],
        },
        {
          type: 'module',
          package: 'authz',
          rules: [{ type: 'rule', name: 'allow', default: true, value: { type: 'value', value: true } }],
        },
      ],
    },
    'authz',
    'allow',
  ),
  -1,
);

check(
  'two definitions agreeing on true -> allow, no conflict',
  decideAddressed(
    { user: { role: 'admin' } },
    {
      type: 'modules',
      modules: [
        {
          type: 'module',
          package: 'authz',
          rules: [
            { type: 'rule', name: 'allow', body: [{ type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } }] },
            { type: 'rule', name: 'allow', body: [{ type: 'value', value: true }] },
          ],
        },
      ],
    },
    'authz',
    'allow',
  ),
  1,
);

// ---------------------------------------------------------------------------
// 16. Parser agreement with the backend. zopa and the service behind
//     it read the same bytes, so anywhere the two parsers could
//     disagree is a place to smuggle a value past a policy.
// ---------------------------------------------------------------------------
{
  // Duplicate keys: Go, JavaScript, and OPA all keep the last one.
  const dupPolicy = { type: 'eq', left: refRole, right: { type: 'value', value: 'admin' } };
  const dupBytes = enc.encode('{"user":{"role":"admin","role":"guest"}}');
  const i = writeBytes(dupBytes);
  const a = writeJson(dupPolicy);
  const r = evaluate(i.ptr, i.len, a.ptr, a.len);
  freeBuf(i);
  freeBuf(a);
  check('duplicate input keys resolve last-wins -> deny', r, 0);
}

for (const bad of ['{"n":01}', '{"n":1.}', '{"n":.5}', '{"n":+1}', '{"n":1e}']) {
  const i = writeBytes(enc.encode(bad));
  const a = writeJson({ type: 'value', value: true });
  const r = evaluate(i.ptr, i.len, a.ptr, a.len);
  freeBuf(i);
  freeBuf(a);
  check(`non-JSON number ${bad} is rejected -> -1`, r, -1);
}

// ---------------------------------------------------------------------------
// 17. body_truncated: the shim refuses an oversized body before it
//     gets here, but the flag is part of the body input shape and a
//     policy is allowed to key on it directly.
// ---------------------------------------------------------------------------
const truncationPolicy = {
  type: 'module',
  rules: [
    { type: 'rule', name: 'allow_body', default: true, value: { type: 'value', value: true } },
    {
      type: 'rule',
      name: 'allow_body',
      body: [{ type: 'ref', path: ['input', 'body_truncated'] }],
      value: { type: 'value', value: false },
    },
  ],
};
check(
  'body_truncated=true -> policy can deny',
  decideTarget({ body: null, body_raw: '{"a":1', body_truncated: true }, truncationPolicy, 'allow_body'),
  0,
);
check(
  'body_truncated=false -> default allows',
  decideTarget({ body: { a: 1 }, body_raw: '{"a":1}', body_truncated: false }, truncationPolicy, 'allow_body'),
  1,
);

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  exit(1);
} else {
  console.log(`\nall tests passed`);
}
