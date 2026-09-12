// Cedar via its official WASM binding, in-process.
//
// The proposal listed Cedar as a native baseline and an earlier
// revision of bench/README.md said no first-party binding was reachable
// from Node. That was wrong: `@cedar-policy/cedar-wasm` is published by
// the Cedar project and its `nodejs` entry point runs directly under
// `node`.
//
// It is not vendored. The engine resolves the package if the host has
// installed it and skips itself, by name, if not -- the same contract
// the OPA engines have with the `opa` CLI. This repository still has no
// package.json and no committed dependency.
//
// Cedar is not a proxy-wasm engine and is not competing for the same
// deployment; it is here because the README names it in the comparison
// table and the benchmark proposal asked for it.
//
// Read the number with its caveat. The policy set is preparsed and
// evaluated through `statefulIsAuthorized`, which is the fair analogue
// of `zopa-compiled` and of OPA's prebuilt wasm -- charging Cedar a
// policy parse per decision would be the same unfairness this harness
// avoids for OPA by keeping `opa build` out of cold start. Even so most
// of what is measured here is the wasm-bindgen boundary: every call
// serialises principal, action, resource, context and entities into the
// module and deserialises an answer out. Preparsing the policy takes it
// from ~60 us to ~29 us, so the remainder is not policy compilation.
// This is a measurement of Cedar-through-its-WASM-binding, not of
// Cedar's evaluator, and it should not be read as the latter.

import { createRequire } from 'node:module';

export const id = 'cedar';
export const label = 'Cedar (wasm binding)';

const PACKAGE = '@cedar-policy/cedar-wasm/nodejs';

// Cedar decides over (principal, action, resource, context) rather than
// a single input document. Every fixture's input goes in `context`
// against fixed placeholder entities, which is the mapping the fixtures'
// own `cedar` policies are written against: they read `context.*` where
// the Rego reads `input.*`. Nothing here depends on entity data, so no
// entity store or schema is needed.
const PRINCIPAL = { type: 'User', id: 'alice' };
const ACTION = { type: 'Action', id: 'access' };
const RESOURCE = { type: 'Resource', id: 'r' };

function load() {
  // A bare `import` would make this module unloadable when the package
  // is absent, which would take the whole harness down instead of
  // skipping one engine.
  const require = createRequire(import.meta.url);
  return require(PACKAGE);
}

export async function available() {
  try {
    const cedar = load();
    return { ok: true, note: `cedar ${cedar.getCedarVersion?.() ?? 'unknown'}` };
  } catch {
    return {
      ok: false,
      reason: `${PACKAGE} not installed (npm i --no-save @cedar-policy/cedar-wasm)`,
    };
  }
}

// Only fixtures carrying a Cedar policy. Writing one on the fly from the
// Rego would be guessing at a semantic mapping, and the agreement gate
// exists precisely so nothing here is guessed at.
export function supports(fixture) {
  return typeof fixture.cedar === 'string' && fixture.cedar.length > 0;
}

// The preparsed policy set lives in the binding's thread-local cache,
// keyed by this id. Fixtures each get their own so one cannot answer
// for another.
let nextPolicySetId = 0;

export async function setup(fixture) {
  const cedar = load();

  const policySetId = `zopa-bench-${nextPolicySetId++}`;
  const parsed = cedar.preparsePolicySet(policySetId, { staticPolicies: fixture.cedar });
  if (parsed.type !== 'success') {
    throw new Error(`cedar: ${fixture.name}: ${JSON.stringify(parsed.errors ?? parsed)}`);
  }

  const call = {
    principal: PRINCIPAL,
    action: ACTION,
    resource: RESOURCE,
    context: fixture.input,
    preparsedPolicySetId: policySetId,
    entities: [],
    validateRequest: false,
  };

  // A failure here has to surface at setup rather than as a per-decision
  // deny, which the agreement gate would report as a policy
  // disagreement and send someone hunting the wrong bug.
  const probe = cedar.statefulIsAuthorized(call);
  if (probe.type !== 'success') {
    throw new Error(`cedar: ${fixture.name}: ${JSON.stringify(probe.errors ?? probe)}`);
  }

  return {
    decide(nextInput) {
      if (nextInput !== undefined) call.context = nextInput;
      const result = cedar.statefulIsAuthorized(call);
      if (result.type !== 'success') return -1;
      // Cedar is deny-by-default with no third state, so there is no
      // undefined to map: allow is 1 and everything else denies.
      return result.response.decision === 'allow' ? 1 : 0;
    },
    // The binding owns its own wasm instance and does not expose the
    // memory object, so there is no comparable linear-memory figure to
    // report. Reporting the Node process RSS instead would measure the
    // harness, not Cedar.
    memoryBytes() {
      return null;
    },
    close() {},
  };
}
