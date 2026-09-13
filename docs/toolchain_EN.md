# Toolchain and end-to-end flow

This document records the complete path **from capability specification to executable
enforcement**, what each tool does, and which gate runs at which stage.
How to write a rule file: [`rule-authoring_EN.md`](rule-authoring_EN.md).  Layering and
semantics: [`capability-language-layers.md`](capability-language-layers.md).

> 中文版：[toolchain.md](toolchain.md)

## 1. End-to-end flow

```
1) Capability specification (written by a human)
   capability.json (scheme / capabilities / params_schema / roles)
      ├─ cmd/sign        → .p7s                  (signature)
      ├─ cmd/verify                              (verify; non-zero exit on failure)
      ├─ gen-docs        → *-capabilities.md     (human/AI-readable semantics; the AI's input)
      └─ gen-backfill                            (attach params_schema digests; drift detection)

2) Requirement → least-privilege capability list (AI)
   AI_PROMPT.md + task description → LLM → claims.json
      └─ gen-capability -schemes <data> [-minimal]
                                    (legality / redundancy / over-privilege + parameter contract;
                                     emits the minimal set as JSON, with scheme_version pinned)

3) Issuance (embed the list into the identity)
   pki-client aic issue --from-claims claims.json
      → derives --caps (with JSON parameters), --pa defaults to the same set (least privilege)
      → the claims file digest is anchored into the signed DA (server audit: claims=sha256:…)
      → capabilities are embedded into the AIC extension / DA

4) Rules (execution-side policy)
   gen-rule -schemes <data> -claims claims.json -out rules/
      ├─ structure + unknown-field validation, and the parameter contract (the same one as in 2)
      └─ optional -template carries conditions / constraints / flow
   demo/rule-exec -publish rules/ -out published/
      → v<maj>.<min>.json(.p7s) + default.json(.p7s) + manifest.json

5) Load and execute
   verify signature → structure → rule capability ⊆ signer's own AIC grant
     → condition evaluation → op|if|seq → parameterized SQL
```

The key point: **steps 2 and 4 use the same parameter contract**
(`registry.ValidateParams`), so "the capability signed into the AIC" and "the capability
declared in the rule" cannot diverge; and there is **no manual copying** between 2 and 4
(`--from-claims` consumes 2's output directly).

## 2. Tools

| Tool | Function | Usage |
|---|---|---|
| `gen-authz` | capability scheme → `authz.json` (roles / ou_mapping / gateway_namespaces / capability_parameters) | `go run ./cmd/gen-authz -out /tmp/authz.json <scheme.json> [...]` (`-list` to list capabilities) |
| `gen-docs` | scheme → markdown permission documentation (human/AI-readable) | `go run ./cmd/gen-docs <scheme.json>`; `-all <data-dir>` for every scheme; `-out` for the path |
| `gen-capability` | validate AI capability claims (legality / redundancy / over-privilege); emit the minimal set | `go run ./cmd/gen-capability -schemes <data-dir> [-minimal] [-grants a,b] claims.json` |
| **`gen-rule`** | generate rule skeletons from a validated capability list; **writes nothing unless both gates pass** | `go run ./cmd/gen-rule -schemes <data-dir> -claims claims.json -out rules/ [-template t.json] [-version 1.0] [-force]` |
| `gen-backfill` | insert `params_schema_digest` (verifies declared digests for drift; preserves every other byte) | `go run ./cmd/gen-backfill <data-dir>` |
| `sign` | PKCS#7 sign, producing a detached `.p7s` | `go run ./cmd/sign -cert c.pem -key k.pem -in v1.json [-out v1.json.p7s]` |
| `verify` | verify a signature up to a trust root (non-zero exit on failure) | `go run ./cmd/verify -in v1.json [-sig v1.json.p7s] -CA root.pem` |
| `vectors-run` | run the CLC-v1 conformance corpus (verdict + normative reason + merged result) | `CLC_VECTORS=<vectors.json> go run ./cmd/vectors-run/` |
| `demo/rule-exec` | rule end-to-end demo; `-publish` publishes rules; `-sql` prints only the generated SQL | `go run ./demo/rule-exec [-publish rules/ -out published/]` |

Except for `vectors-run` (a pure runner that takes `CLC_VECTORS`), every tool prints its
purpose and flags with `-h`.

## 3. Three common scenarios

```bash
# A. Capability specification only
export CAPABILITY_DIR=../capability/data
go run ./demo -data $CAPABILITY_DIR list            # list every capability
go run ./cmd/gen-docs -all $CAPABILITY_DIR           # human/AI-readable docs

# B. Requirement → issuance (with an LLM in the loop)
#    the LLM produces claims.json following AI_PROMPT.md; validate, then issue
go run ./cmd/gen-capability -schemes $CAPABILITY_DIR -minimal claims.json > minimal.json
pki-client <cfg> aic issue --from-claims minimal.json --agent <id> --user-cert <c> --user-key <k>

# C. Capability list → executable rule
go run ./cmd/gen-rule -schemes $CAPABILITY_DIR -claims minimal.json -out rules/
go run ./demo/rule-exec -publish rules/ -out published/
```

## 4. Gate matrix

| Stage | Signature | Structure / unknown fields | Parameter contract (registry) | Signer's grant boundary |
|---|---|---|---|---|
| `gen-capability` (claims) | — | — | ✅ | over-privilege check against given grants |
| `gen-rule` (generate rule) | — | ✅ | ✅ | — |
| `rule-exec -publish` | ✅ sign | ✅ | ✗ | ✗ |
| `LoadRulePlugin` (load) | ✅ verify | ✅ | ✗ | ✅ |
| `gen-backfill` (data) | — | — | digest drift check | — |
| `vectors-run` / property tests | — | — | CLC semantic conformance (105 vectors + 1184 property cases) | — |

**Known gap:** the parameter contract only runs on the generation path
(`gen-capability` / `gen-rule`).  A hand-written rule can bypass it, be signed and be
loaded.  Direction: thread the registry (or a validation hook) into publish and load.

## 5. Relationship to the design principles

The decision-layer principles (P1–P12) live in the capability repository:
[`capability-language-core-principles-v1.md`](https://github.com/varwof/capability/blob/main/docs/capability-language-core-principles-v1.md).
The rule layer and toolchain follow the same discipline, expressed as these engineering
constraints:

| # | Discipline | Where it lands |
|---|---|---|
| D1 | **One contract, many consumers** | claims and rules share `registry.ValidateParams`; the rule file shape is guarded by schema ↔ struct agreement |
| D2 | **Fail-closed by default** | unknown field / parameter / step kind / constraint / over-budget are all rejected |
| D3 | **All or nothing** | `gen-rule` writes no file when any claim fails; publish validates every version before signing |
| D4 | **A gate must cover every entry point** | the parameter contract runs only on the generation path ⇒ hand-written rules bypass it (current gap, §4) |
| D5 | **Every artifact needs a gate** | generated docs and digests drift unless CI checks them; add a gate or do not commit them |

## 6. Conformance checks

```bash
# Decision layer (three implementations + property tests)
CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json go run ./cmd/vectors-run/
go test ./semantics/ -run TestIntersectionProperty -v
python3 ../aic-capability-demo/property_test.py
(cd ../aic-capability-demo/ts && node --experimental-strip-types vectors-run.ts)

# Rule layer
go test ./ruleexec/ ./cmd/gen-rule/ -v        # rule validation, publication boundary, parameter-contract guard
go run ./demo/rule-exec                        # rule → signature → validation → conditions → flow
```

Current state: CLC corpus 105/105 in Go, Python and TypeScript (covering the
rev CLC-1.3 `allow_unresolved` verdict and §9.3 multi-grant aggregation); P11 property 1184 cases with
0 failures in all three; property cases reproducible (byte-identical regeneration); OCMP
offline vectors 12 cases covering 11/11 normative codes; rule-layer tests green; the
TypeScript mirror 3/3; SQL parity 4/4.
