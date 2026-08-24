# Capability Register

A registry of standard capability definitions for fine-grained AI Agent permission control.
Capability specifications are carried by **executable JSON files** (capability.json), support PKCS#7 signatures,
and can **generate authz.json authorization policies** from the spec files (gen-authz tool).

## Design Philosophy

```
Vendor registers capabilities         Agent queries capabilities
┌──────────────┐          ┌──────────┐
│ varwof/core  │          │ Agent A  │
│ core:        │◄────────►│ holds AIC │
│  cert:issue  │          │ declares capabilities │
│  ca:list     │          └──────────┘
└──────────────┘
     Globally unified rules: same product, same capability definitions
     Single source: capability.json → gen-authz → authz.json
```

## scheme_id Naming Convention

| Type | Format | Example |
|------|--------|---------|
| **Public standard** | `<vendor>/<product>` | `varwof/core`, `varwof/gateway`, `oracle/mysql` |
| **Private extension** | `x-<vendor>/<product>` | `x-vendor/acme` |
| **System constraint** | `varwof/constraint-v1` | Fixed, cannot be private |

- Directory layout: `<root>/<vendor>/<product>/v<version>.json`
- The `x-` prefix marks private extensions, consistent with the HTTP `X-` header convention
- Full capability identifier: `vendor/product:capability_id` (e.g., `varwof/core:cert:issue`)

## Directory Structure

```
register/
├── schema.go              # Capability definition structs (SchemeDefinition/CapabilityEntry/RoleDef)
├── registry.go            # Register/query/validate
├── validator.go           # Permission validation engine (MatchCapability/ValidateRoles)
├── genauthz.go            # authz.json generator (GenAuthz/GenAuthzToFile)
├── gendocs.go             # Markdown permission documentation generator (GenDocs)
├── mincap.go              # Least-privilege validator (valid/redundant/over-privileged detection)
├── loader.go              # Embedded/disk loader
├── sign.go                # PKCS#7 sign/verify
├── AI_PROMPT.md           # AI least-privilege capability generation prompt template
├── cmd/
│   ├── gen-authz/         # Tool to generate authz.json from capability.json
│   ├── gen-docs/          # Generate markdown permission docs from capability.json
│   ├── gen-capability/    # Validate AI-generated capability sets + least-privilege suggestions
│   ├── sign/              # Sign capability.json (.p7s)
│   └── verify/            # Verify capability.json signatures
├── demo/main.go           # Demo program
├── docs/                  # Documentation
│   ├── quickstart.md      # Quick start
│   ├── reference.md       # API reference
│   └── architecture.md    # Architecture design
│
├── varwof/
│   ├── core/              # varwof/core: PKI core permissions (37 capabilities + 10 roles)
│   ├── gateway/           # varwof/gateway: gateway permissions (21 capabilities + 5 roles)
│   └── constraint/        # varwof/constraint-v1: system constraints
├── oracle/
│   └── mysql/             # oracle/mysql: MySQL operation permissions
└── x-vendor/
    └── acme/              # Private extension example
```

## Quick Start

```bash
cd register

# List all capabilities
go run ./cmd/gen-authz -list varwof/core/v1.json varwof/gateway/v1.json

# View a product's capabilities
go run ./demo get varwof/core

# Generate authz.json (core authorization policy)
go run ./cmd/gen-authz -out /tmp/authz.json varwof/core/v1.json varwof/gateway/v1.json

# Validate a single capability
go run ./demo validate varwof/core:cert:issue

# Batch validation
go run ./demo check varwof/core:cert:issue varwof/gateway:proxy:http

# Check subset relations
go run ./demo subset 'varwof/core:cert:issue,varwof/core:ca:list' 'varwof/core:cert:*'

# Search capabilities
go run ./demo search issue
```

## gen-authz: Generate Authorization Policies from Specs

authz.json is a **derived artifact**, generated from capability.json (the authoritative spec) to avoid manual-maintenance drift.

```bash
# Generate authz.json (roles + OU mapping + gateway namespaces + parameter defaults)
go run ./cmd/gen-authz -out /tmp/authz.json \
    varwof/core/v1.json \
    varwof/gateway/v1.json

# Signature protection (enforces verification when capability.json has a .p7s; errors if missing)
go run ./cmd/gen-authz -verify-required -trust-roots ca.pem \
    -out /tmp/authz.json varwof/core/v1.json

# List only the capability catalog
go run ./cmd/gen-authz -list varwof/core/v1.json
```

### Mapping Rules

| capability.json | authz.json |
|---|---|
| Primary scheme `roles` (e.g., varwof/core's admin/operator) | `roles` |
| Role `ous` | `ou_mapping` |
| Namespace roles (`gateway:admin` etc., aggregated across all schemes) | `gateway_namespaces` |
| Capability `parameters.default` | `capability_parameters` (`scheme:cap_id` → default value) |

### Validation

- Non-wildcard grants must be covered by this scheme's capabilities (**error**)
- Wildcard grants (e.g., `gateway:*`) not matched locally are treated as cross-scheme namespace authorizations (**warning**)
- When a `.p7s` signature exists, PKCS#7 verification is enforced (`-verify-required`)

## gen-docs: Generate Permission Documentation from Specs

Each capability.json can generate a **human/AI-readable markdown permission document**,
fully describing each capability's semantics (when needed / when not to grant / examples / parameters),
serving as the basis for AI-generated least-privilege capabilities.

```bash
# Generate permission docs for varwof/core and varwof/gateway
go run ./cmd/gen-docs varwof/core/v1.json varwof/gateway/v1.json

# Directory mode: generate all schemes at once
go run ./cmd/gen-docs -all register/
```

The generated documents (`core-capabilities.md` / `gateway-capabilities.md`) contain:
capability catalog table, detailed per-capability semantics, wildcards and matching rules, roles and authorization mapping, least-privilege generation guide.

## AI Loop: Task → Least-Privilege Capability → Consumption

**Core goal**: hand the capability specs (JSON + Markdown) to an AI large language model;
the AI automatically generates a **least-privilege** capability set based on the task — a complete loop from generation to consumption.

```
Task description (e.g., "issue a certificate for a production HTTPS service")
    │
    ▼
AI LLM (reads capability.json + capabilities.md + AI_PROMPT.md)
    │  Determines task type, adjudicates per capability, narrows parameters
    ▼
Least-privilege capability set (JSON claims)
    │
    ▼
gen-capability validator (validity + redundancy + over-privilege detection)
    │
    ▼
Least-privilege set ──→ signed into AIC/PA ──→ consumed at gateway (register validation)
```

### Usage Steps

1. **Prepare materials** (built in):
   - `varwof/core/v1.json` + `varwof/core/core-capabilities.md`
   - `varwof/gateway/v1.json` + `varwof/gateway/gateway-capabilities.md`
   - `AI_PROMPT.md` (complete prompt template guiding the AI)

2. **AI generates**: give the above materials + task description to the AI; the AI outputs a claims JSON file.

3. **Machine validation**:

```bash
# Validate validity (scheme/capability/parameter) + redundancy + over-privilege detection
go run ./cmd/gen-capability -grants "cert:issue,ca:list,ca:info" claims.json

# Output least-privilege set suggestions
go run ./cmd/gen-capability -grants "cert:issue,ca:list,ca:info" -minimal claims.json
```

4. **Consumption**: the validated least-privilege set is signed into AIC/PA; gateways authorize on the data plane accordingly.

### Validation Capabilities

`gen-capability` detects three classes of problems:

| Category | Description | Example |
|----------|-------------|---------|
| **Invalid declaration** | Unknown scheme / nonexistent capability / undefined parameter | `bogus/vendor:foo:bar` |
| **Redundant declaration** | Covered by a wildcard or duplicated | `ca:list` covered by `ca:*` |
| **Over-privileged capability** | Not authorized by identity grants | `key:recover` not in grants |

Once validation passes (`least_privilege: true`), it is ready for signing.

## Runtime Integration (Phase D: register authoritative schema → runtime validation)

Beyond generating derived artifacts, the capability spec loop also performs **capability registration validation** at runtime (fail-closed):
capabilities declared in an AIC must come from register schemes; unregistered scheme/capability declarations are rejected.

### core (issuance side)

- Config item `capability_schemes` (empty = embedded schemes; directory specified = disk override)
- On startup/`reloadConfigNowWithMuxes`: `loadCapRegistry` → `Server.SetCapRegistry`
- When issuing AIC / agent-proxy certificates, all capabilities are validated via the `SignConfig.ValidateCapabilities` hook
  (`internal/capregistry`, embedded first + disk override + hot-reload atomic replacement)

### Three Gateways (data plane, opt-in)

- Config item `capability_schemes` (`gateway/http`, `gateway/tcp`, `gateway/udp`)
- **Enabled only when explicitly configured** (backward compatible: no validation by default; legacy AICs unaffected)
- Unified loading via `gateway/capreg.Loader` (embedded first + disk override); injected via `gw.SetGlobalCapabilityRegistry` on `NewGateway`/`Reload`;
  pipeline stage one in `RunAccessPipeline` validates EffectiveCaps are registered — unregistered → reject connection + audit
- Edit disk scheme JSON → SIGHUP hot reload takes effect immediately

## How to Register New Capabilities

### Public Standard

1. Fork the repository
2. Create a directory under `register/<vendor>/<product>/` (e.g., `varwof/core/`)
3. Add `v1.json` (see format below; scheme_id uses `<vendor>/<product>`)
4. Sign with `go run ./cmd/sign` to produce `.p7s`
5. Submit a PR; published after review

### Private Extension

1. Create an `x-<your-vendor>/` directory under `register/`
2. Add `v1.json` (scheme_id uses `x-<your-vendor>/<product>`)
3. Usable directly, no review required

## capability.json Format

```json
{
  "scheme_id": "varwof/core",
  "name": "Varwof PKI Core",
  "version": "1.1.0",
  "description": "Varwof PKI 核心引擎操作权限",
  "vendor": "varwof",
  "product": "core",
  "capabilities": [
    {
      "id": "cert:issue",
      "description": "签发证书",
      "parameters": {
        "max_validity_days": {
          "type": "int",
          "description": "最大有效期（天）",
          "default": 365,
          "min": 1,
          "max": 3650
        }
      }
    }
  ],
  "roles": {
    "admin": {
      "display_name": "管理员",
      "profiles": ["m-admin"],
      "ous": ["admin", "Admin"],
      "grants": ["ca:list", "cert:issue", "cert:revoke"]
    },
    "agent": {
      "display_name": "AI Agent",
      "profiles": ["agent-proxy"],
      "grants": ["gateway:*"]
    }
  }
}
```

## Field Reference

### SchemeDefinition

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| scheme_id | string | ✅ | Product unique identifier (vendor/product) |
| name | string | ✅ | Product name |
| version | string | ✅ | Semantic version |
| description | string | ✅ | Product description |
| vendor | string | ✅ | Vendor |
| product | string | ✅ | Product name |
| author | string | | Author |
| license | string | | License |
| homepage | string | | Homepage |
| capabilities | []CapabilityEntry | ✅ | Capability list |
| roles | map[string]RoleDef | | Role definitions (used by gen-authz) |

### RoleDef

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| display_name | string | | Display name |
| profiles | []string | | Associated certificate profiles |
| ous | []string | | Bindable OUs (→ ou_mapping) |
| grants | []string | ✅ | Granted capability list (wildcards supported, e.g., `ca:*`) |

### CapabilityEntry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | ✅ | Capability ID (domain:action, e.g., cert:issue) |
| description | string | ✅ | Capability description |
| parameters | map | | Parameter definitions (defaults → authz capability_parameters) |

### ParameterDef

| Field | Type | Description |
|-------|------|-------------|
| type | string | Parameter type (int/string/bool/list) |
| description | string | Parameter description |
| default | any | Default value |
| min | any | Minimum |
| max | any | Maximum |
| enum | []string | Enumerated values |
| required | bool | Whether required |

## Use in AIC

```go
// Agent declares capabilities
capabilities := []pki.Capability{
    {SchemeId: "varwof/core", CapabilityId: "cert:issue"},
    {SchemeId: "varwof/gateway", CapabilityId: "proxy:http"},
    {SchemeId: "varwof/constraint-v1", CapabilityId: "time:window:0900-1800"},
}

// Gateway validation
reg, _ := register.NewRegistryWithEmbedded()
for _, cap := range capabilities {
    full := cap.SchemeId + ":" + cap.CapabilityId
    if _, _, err := reg.ValidateCapability(full); err != nil {
        // Reject: unregistered capability
    }
}
```

## License

Apache-2.0
