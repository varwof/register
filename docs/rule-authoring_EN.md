# Writing a rule (execution rule)

> ⚠️ **Exploratory** — the rule format has not yet been promoted to a registry-published
> specification.  This document, `demo/rule-exec/rule.schema.json` and `ruleexec.Rule`
> must agree (a test enforces it: `TestRuleSchemaMatchesStruct`).
>
> 中文版：[rule-authoring.md](rule-authoring.md)

A rule describes **what a gateway must additionally satisfy when executing an
already-authorized operation, and in what order to execute it**.  It makes **no
authorization decision** — authorization belongs to the decision layer (CLC-v1 / AIC).
`ruleexec` MUST NOT implement capability-subset or deny semantics itself
(see [`capability-language-layers.md`](capability-language-layers.md)).

## 1. Fields

Machine-readable contract: [`../demo/rule-exec/rule.schema.json`](../demo/rule-exec/rule.schema.json)
(draft-07, `additionalProperties: false`).

| Field | Required | Constraint |
|---|---|---|
| `rule_id` | ✅ | 1–128 bytes, unique (suggested: `<scheme>-<capability>-v<maj>.<min>`) |
| `version` | ✅ | semantic `x.y.z` |
| `scheme` | ✅ | `vendor/product`, must exist in the registry |
| `capability` | ✅ | capability id (without the scheme), must belong to that scheme |
| `params` | ✅ | JSON object; must satisfy the capability's parameter contract (§5) |
| `conditions` | — | runtime-context condition (structured AST, §3) |
| `constraints` | — | constraint references (§4) |
| `flow` | — | finite tree of `op` / `if` / `seq` (§3) |

**Unknown fields are rejected.**  The loader uses `DisallowUnknownFields`, so a
misspelled key (e.g. `condtions`) makes the rule **fail to load** instead of
silently dropping a constraint.  Rules are machine-generated at least as often as
they are hand-written, so field names are not treated leniently.

## 2. Minimal example

```json
{
  "rule_id": "org-a-db-readonly-2026",
  "version": "1.0.0",
  "scheme": "std/database-v1",
  "capability": "query:SELECT",
  "params": {
    "tables": ["customers"],
    "columns": { "customers": ["id", "name"] },
    "filter_columns": { "customers": ["tenant_id"] },
    "row_filter": { "customers": { "and": [ { "column": "tenant_id", "op": "=", "value": "org-a" } ] } },
    "limit": { "max": 100 }
  },
  "conditions": { "op": "and", "items": [ { "op": "eq", "path": "request.tenant_id", "value": "org-a" } ] },
  "constraints": [ { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] } ],
  "flow": {
    "steps": [
      { "name": "query", "kind": "op", "op": "db:select" },
      { "kind": "if", "condition": { "op": "gt", "path": "rowCount", "value": 0 },
        "then": [ { "name": "mark", "kind": "op", "op": "db:update" } ] }
    ]
  }
}
```

## 3. Conditions and flow: closed operator sets

**Condition operators (12, closed):** `and` `or` `not` `is-null` `eq` `neq` `lt` `lte`
`gt` `gte` `in` `between`.  Shape: `{"op": …, "path": …, "value": … | "window": [...] | "items": [...]}`.

Semantics (full rules in [`condition-semantics_EN.md`](condition-semantics_EN.md)):

- two-valued logic; comparison operators are **always false** against `null`/missing —
  only `is-null` tests for "no value";
- **no implicit type conversion**: `"500"` ≠ `500`; string comparison is case-sensitive,
  byte-wise;
- a missing path with a comparison operator is an **error** (not `false`).

**Flow constructs (3, closed):** `op` (atomic operation; its output is merged into task
variables), `if` (branch), `seq` (sequence).  **No loops, no retries** — retries belong
to the caller / job orchestrator, where each attempt is re-authorized.

**Budget (published with the specification; must not be widened):** 10,000 steps /
depth 64 / nesting 64 (`demo/rule-exec/budget-defaults.json`).  Exceeding it terminates execution.

## 4. Constraints

`{"scheme": "varwof/constraint-v1", "id": "<constraint id>", "params": [...]}`.
Only `varwof/constraint-v1` (plus the `constraint` / `constraint-v1` aliases) is accepted;
**an unknown constraint type is rejected** (fail-closed).

## 5. Parameter contract — the same contract the issuance path uses

A rule's `params` must satisfy **the capability's own parameter contract**, which the
registry provides and which is **the same function used for the capability list signed
into an AIC** (`registry.ValidateParams`):

1. if the capability declares `params_schema`, validate against that schema
   (`required`, types, ranges, `oneOf`, …);
2. otherwise apply the flat `parameters` contract (required, types, min/max/enum,
   unknown keys rejected).

The contract is **fail-closed by default**: when a schema declares `properties` but omits
`additionalProperties`, it is treated as a **closed object**, and an undeclared key
(including a misspelled one) is rejected.  To allow free keys, say so explicitly with
`"additionalProperties": true` or a sub-schema.

> This used to be two implementations: the claims path used the data-driven schema
> (enforcing `required`), the rule path used a hard-coded validator that did not check
> `required` and returned `nil` for every other scheme.  As a result, "the capability
> signed into the AIC" and "the capability declared in the rule" could disagree.  Both
> now call `registry.ValidateParams`.

## 6. Write → validate → sign → load

```bash
# 1) Generate a skeleton (recommended: from the validated least-privilege claims,
#    so parameters are never re-typed by hand)
go run ./cmd/gen-rule -schemes <capability-data-dir> -claims claims.json -out rules/
#    -template <rule.json>   carries conditions / constraints / flow
#    -version 1.0            initial version

# 2) Add conditions and flow (by hand or from a template), then publish:
#    structure validation + PKCS#7 signature
go run ./demo/rule-exec -publish rules/ -out published/
#    artifacts: <out>/<scheme>/v<maj>.<min>.json(.p7s) + default.json(.p7s) + manifest

# 3) Load and execute (in-process)
#    ruleexec.LoadRulePlugin(rulePath, trustRoots, handler)
#    ruleexec.RegisterRulePluginsFromDir(outDir, trustRoots, handler)
```

## 7. Gate matrix (which check runs where)

| Stage | Signature | Structure / unknown fields | Parameter contract (registry) | Signer's grant boundary |
|---|---|---|---|---|
| `gen-rule` (generate) | — | ✅ | ✅ | — |
| `-publish` (sign) | ✅ sign | ✅ | ✗ | ✗ |
| `LoadRulePlugin` (load) | ✅ verify | ✅ | ✗ | ✅ |

**Known gap:** the parameter contract currently only runs on the **generation** path.  A
hand-written or otherwise generated rule can be signed, published and loaded without ever
being checked against it (`loadAuthorizedRule` has no registry parameter).  Closing it
means threading the registry (or a validation hook) into the publish/load paths.

## 8. Fail-closed list

| Situation | Result |
|---|---|
| unknown / misspelled field | load fails (no silent constraint loss) |
| unknown step kind or condition operator | load fails |
| unknown constraint scheme | validation fails |
| missing required parameter / unknown parameter / type or range mismatch | validation fails (generation and publish stages) |
| PKCS#7 missing, tampered, untrusted | load fails |
| rule capability outside the **signer's own AIC grant** | load fails (`RuleWithinSignerGrant`) |
| signer certificate carries no AIC extension at all | load fails — the signer must prove it may publish this rule |
| budget exceeded | execution terminates with an explicit error code |

## 8.1 Who may sign a rule

Publication is not gated on the PKCS#7 chain alone.  The loader additionally requires
the signing certificate to carry an **AIC extension** whose grant covers the rule's
capability (`RuleWithinSignerGrant`) — otherwise any holder of a trusted signing
certificate could publish policy that exceeds its own authority.

Consequence for tests and tooling: `ruleexec.GenSignerCert` produces a plain
self-signed certificate and is **not** sufficient to publish a rule.  Use
`ruleexec.GenSignerCertWithCapabilities` / `GenSignerCertWithGrant` to build a signer
that carries the grant the rule needs.

## 9. Relation to the capability list

A rule and the capability list embedded in an AIC describe **two halves of the same
thing**: the list says *what is allowed*, the rule says *what must additionally hold at
execution time*.  They therefore share one parameter contract (§5), and at load time the
rule must additionally prove it does not exceed the signer's own authority (§8).

Current model limitation: **one rule is registered per scheme** (the plugin holds a single
`Rule`; the publish directory loads only the highest minor as `default.json`).  For several
policies, split into different schemes or merge them into one rule via a template —
`gen-rule` warns explicitly when a scheme gets more than one rule.
