# Developer Documentation

## Directory Structure

```
register/
├── schema.go          # Capability definition structs
├── registry.go        # Register/query/validate
├── validator.go       # Permission validation engine
├── loader.go          # Embedded/disk loader
├── sign.go            # PKCS#7 sign/verify
├── demo/main.go       # Demo program
│
├── docs/              # User documentation
├── dev-docs/          # Developer documentation (this directory)
│
├── varwof/            # First-party product capability definitions
├── oracle/            # Third-party products
└── x-vendor/          # Private extension example
```

## Development Guide

### Adding a New Product

1. Create `v1.json` under `register/<vendor>/<product>/`
2. Fill in capability.json (see SchemeDefinition in schema.go)
3. Run `go run ./demo list` to verify
4. Submit a PR

### Modifying Existing Capabilities

1. Edit `register/<vendor>/<product>/vN.json`
2. Increment the version number (v1.json → v2.json)
3. Keep old versions (backward compatibility)
4. Run tests to verify

### Signing Workflow

```bash
# 1. Generate the product key pair
openssl ecparam -genkey -name prime256v1 -out product.key
openssl req -new -x509 -key product.key -out product.pem -days 365

# 2. Sign capability.json
go run ./sign -cert product.pem -key product.key -in v1.json -out v1.json.p7s

# 3. Verify
go run ./verify -in v1.json -sig v1.json.p7s -CA pki/root-ca.pem
```

### Testing

```bash
# Run all tests
go test ./...

# Run specific tests
go test -run TestValidate -v

# Build verification
go build ./...
go vet ./...
```

### Embedded Loading

New capability definitions are automatically embedded into the binary via `go:embed`. Update the embed directives in `loader.go`:

```go
//go:embed varwof/core/*.json varwof/gateway/*.json varwof/constraint/*.json
//go:embed oracle/mysql/*.json
//go:embed x-vendor/acme/*.json
var embeddedSchemes embed.FS
```

After adding a new product, update these directives.

## Code Conventions

### Naming

- scheme_id: `vendor/product` (lowercase, hyphenated)
- capability_id: `category:action[:target]` (lowercase)
- File names: `v1.json`, `v2.json` (semantic versioning)

### JSON Format

- 2-space indentation
- Field order: scheme_id, name, version, description, vendor, product, ...
- Required fields must not be omitted

### Commit Conventions

- feat: add capability definitions
- fix: fix capability definitions
- docs: update documentation
- refactor: refactor code

## Related Projects

- `github.com/varwof/pkcs7` — PKCS#7 sign/verify
- `github.com/varwof/types` — AIC type definitions
- `github.com/varwof/gateway-core` — Gateway security engine
