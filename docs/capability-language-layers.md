# Capability language layers: decision (CLC-v1) vs execution (ruleexec)

> **Terminology (2026-09-13)**: read "layers" here as two **orthogonal axes** — the decision axis
> (CLC: does this call count as doing what was authorized) and the execution axis (ruleexec: act now,
> with bounded flow and what gets recorded).  Across both run the **authorization face** and the
> **evidence face**; a composition draft (ACA) is a contract over the two axes, not a third layer.
> See `dev-docs/aic/zh/26-layer-boundary-and-complexity.md` for the boundary matrix.

One language, two axes:

```
CLC-v1 (decision, no control flow)  ->  ruleexec (execution: conditions/flow/SQL, budgets)  ->  effects
```

| Concern | Owner | Notes |
|---|---|---|
| Capability grammar, entailment, parameter domains, intersection, decision, reason codes | CLC-v1 (`semantics/`) | pure, deterministic, fail-closed |
| Generic parameter semantics (null, explicit empty bound, subset) | CLC-v1 (`semantics.ValidateGrantParams`) | one definition, consumed everywhere |
| Scheme-specific parameter contract (e.g. database-v1 SELECT structure) | the scheme (`register.ValidateSchemeParams`) | lives with the scheme, not with the engine |
| Runtime context conditions (variables, request fields, roles) | ruleexec | must not decide authorization |
| Optional profile artifacts (decision record, envelope, source chain, freshness context, challenge) | CLC-v1 `semantics/` | **default off**; a deployment that only decides online pays none of them |
| Execution flow, budgets, SQL/HTTP invocation, retries | ruleexec | bounded; wall-clock timeout removed from published defaults |

Two rules:

1. **CLC-v1 MUST NOT gain control flow** (loops, recursion, user procedures) — that would
   destroy determinism and mechanical verification.
2. **ruleexec MUST NOT implement capability subset/deny semantics itself** — it calls CLC-v1.

Removed from the execution-side language on 2026-09-10 (to avoid duplication):
`time-in` (time windows belong to authorization constraints), `contains`,
`Rule.roles` (unused; roles belong to the credential/principal layer),
the hard-coded `validateSelectParams` (replaced by the registry-owned scheme
contract + CLC generic semantics), `wall_clock_ms` in the published budget
defaults (non-deterministic; ceilings are now enforced), the **loops**
(`while` / `for`, plus `break` / `continue`), and later **retries**
(`retry` / `max_retries`) together with the **iteration budget**
(`max_iterations` / `KindIterations`).  The remaining flow constructs are
`op | if | seq` and the remaining budgets are steps / depth / nesting, so
termination is structural, there is no amplification factor (one authorization
triggers at most one execution of each operation), and retries belong to the
caller or job orchestrator, where each attempt is re-authorized.

## Publication boundary (rule signing)

A signed rule is not trusted merely because its PKCS#7 signature chains to a
trusted anchor.  `ruleexec` additionally enforces, at load time:

1. the signer certificate MUST carry an AIC extension;
2. the capability the rule declares MUST be covered by the signer's own AIC
   grant — checked with the CLC-v1 entailment semantics
   (`semantics.Entails(grant, operation)`), including parameter bounds;
3. every constraint the rule declares MUST also be declared by the signer.

Any failure aborts loading (fail-closed).  Rationale: without this check any
holder of a trusted signing certificate could publish a rule that exceeds its
own authority.  Implementation: `ruleexec/signer_grant.go`
(`RuleWithinSignerGrant`), wired into `loadAuthorizedRule` so both
`LoadRulePlugin` and `RegisterRulePluginsFromDir` enforce it.

Verified by `ruleexec/signer_grant_test.go` (unit cases: covering grant,
unrelated capability, bound too tight, missing constraint, no AIC) and
`TestPluginLoadEnforcesSignerGrant` (end-to-end: sign → register).
