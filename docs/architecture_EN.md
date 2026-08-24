# Architecture

## Trust Chain

```
Varwof Root CA (offline cold backup)
    │
    ├── Policy Sub-CA
    │       │
    │       ├── Register Sub-CA (capability registration sub-CA)
    │       │       │
    │       │       ├── oracle/mysql (product certificate)
    │       │       ├── varwof/core
    │       │       ├── varwof/gateway
    │       │       └── x-vendor/acme
    │       │
    │       └── (future: Audit Sub-CA etc.)
    │
    └── Issuing Sub-CA (end-entity certificates)
```

## Security Isolation

| Layer | Certificate | Impact if Compromised | Recovery |
|-------|-------------|----------------------|----------|
| L0 | Root CA | Entire set discarded | Redeploy |
| L1 | Policy Sub-CA | Policy layer | Root revokes and re-signs |
| L2 | Register Sub-CA | Product certificates | Policy revokes and re-signs |
| L3 | Product certificate | That product only | Register revokes and re-signs |

## Validation Flow

```
1. Agent declares capabilities → AIC
2. Gateway loads the Register
3. Validate one by one → valid/invalid
4. Subset check → over-privileged/compliant
5. Allow/reject
```

## Signing Flow

```
Vendor signs capability.json → .p7s
Register verifies signature chain → publishes
Agent/gateway verifies .p7s → trusts
```

## Directory Structure

```
register/
├── data/                        ← scheme JSON definitions (pure data)
│   ├── varwof/                  # First-party products
│   │   ├── core/v1.json
│   │   ├── gateway/v1.json
│   │   ├── constraint/v1.json
│   │   └── demo-mysql/v1/v1.json
│   ├── oracle/                  # Third-party
│   │   └── mysql/v1.json
│   └── x-vendor/                # Private extensions
│       └── acme/v1.json
├── loader.go                    ← Go code (go:embed data/)
├── schema.go
├── registry.go
└── ...
```

## Version Management

### Scheme ID Naming

Format: `{vendor}/{product}-v{major}`

- `varwof/demo-mysql-v1` — major version 1
- `varwof/demo-mysql-v2` — major version 2 (breaking change)
- `oracle/mysql-v3` — major version 3

The major version is embedded in scheme_id, ensuring that on breaking changes:
1. Old and new schemes are **registered simultaneously**, not breaking existing certificates
2. Both schemes coexist during migration
3. The old scheme can continue issuing; the new scheme takes over gradually

### Directory Structure

```
register/data/{vendor}/{product}-v{major}/
├── v1.json    ← minor version 1 (initial)
├── v2.json    ← minor version 2 (backward compatible, new capabilities/parameters)
└── v3.json    ← minor version 3 (backward compatible)
```

### Version Compatibility Rules

| Change Type | Compatibility | Approach |
|-------------|---------------|----------|
| New capability (e.g., `TRUNCATE:*`) | ✅ Backward compatible | Add a minor-version JSON; capabilities are a superset of the old version |
| New parameter (with default) | ✅ Backward compatible | Add a minor-version JSON; parameter carries a default |
| Removed/split capability | ❌ Breaking | Create a new major-version directory (`v2/`), new scheme_id |
| Parameter semantic change | ❌ Breaking | Create a new major-version directory (`v2/`), new scheme_id |

### Grant Format

```
{scheme_id}:{capability_id}
```

Examples:
- `varwof/demo-mysql-v1:SELECT:*` — matches v1's latest minor version
- `varwof/demo-mysql-v2:DELETE:*` — matches v2's latest minor version

Loader behavior: looks up by scheme_id; when multiple minor-version JSONs share a scheme_id, the latest is used.

### Migration Flow

```
1. Publish v2 (new scheme_id: varwof/demo-mysql-v2)
2. authz.json adds both v1 and v2 roles
3. Newly issued AICs use the v2 scheme_id
4. Old AICs age out naturally on expiry
5. Migration complete, remove v1
```

## Extension Methods

### Public Standard (v1 scheme)

```bash
mkdir -p register/data/{vendor}/{product}-v1
cat > register/data/{vendor}/{product}-v1/v1.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v1",
  ...
}
EOF
```

### Major Version Upgrade (breaking change)

```bash
mkdir -p register/data/{vendor}/{product}-v2
cat > register/data/{vendor}/{product}-v2/v1.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v2",
  ...
}
EOF
```

### Minor Version Upgrade (backward compatible)

```bash
cat > register/data/{vendor}/{product}-v1/v2.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v1",
  "version": "1.2.0",
  "capabilities": [
    ... (keep old capabilities + additions)
  ]
}
EOF
```

### Private Extension

```bash
mkdir register/data/x-{vendor}/{product}-v1
cat > register/data/x-{vendor}/{product}-v1/v1.json << 'EOF'
{
  "scheme_id": "x-{vendor}/{product}-v1",
  ...
}
EOF
```
