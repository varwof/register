# API Reference

## Schema

### SchemeID Format

Format: `{vendor}/{product}-v{major}`

- `varwof/demo-mysql-v1` — major version 1
- `varwof/demo-mysql-v2` — major version 2 (breaking change)
- `oracle/mysql-v3` — major version 3

Validation rules:
- vendor: lowercase letters + digits + hyphens
- product: lowercase letters + digits + hyphens + `-v{N}` suffix
- Must contain `/` separating vendor and product

### SchemeDefinition

```go
type SchemeDefinition struct {
    SchemeID     string            `json:"scheme_id"`      // vendor/product
    Name         string            `json:"name"`
    Version      string            `json:"version"`        // semver
    Description  string            `json:"description"`
    Vendor       string            `json:"vendor"`
    Product      string            `json:"product"`
    Author       string            `json:"author,omitempty"`
    License      string            `json:"license,omitempty"`
    Homepage     string            `json:"homepage,omitempty"`
    Capabilities []CapabilityEntry `json:"capabilities"`
    Roles        map[string]RoleDef `json:"roles,omitempty"` // used by gen-authz
}
```

### RoleDef

```go
type RoleDef struct {
    DisplayName string   `json:"display_name,omitempty"`
    Profiles    []string `json:"profiles,omitempty"`
    Grants      []string `json:"grants"`
    OUs         []string `json:"ous,omitempty"`
}
```

Role definition: grants reference this scheme's capability_id (wildcards supported, e.g., `ca:*`);
OUs are expanded into ou_mapping by gen-authz.

### CapabilityEntry

```go
type CapabilityEntry struct {
    ID          string                  `json:"id"`
    Description string                  `json:"description"`
    Parameters  map[string]ParameterDef `json:"parameters,omitempty"`
    // AI-friendly semantic fields (used by gen-docs to generate permission docs)
    Summary  string   `json:"summary,omitempty"`
    Usage    string   `json:"usage,omitempty"`    // when the capability is needed
    WhenNot  string   `json:"when_not,omitempty"` // when it should not be granted
    Examples []string `json:"examples,omitempty"`
    Related  []string `json:"related,omitempty"`
}
```

### ParameterDef

```go
type ParameterDef struct {
    Type        string      `json:"type"`        // int/string/bool/list
    Description string      `json:"description,omitempty"`
    Default     interface{} `json:"default,omitempty"`
    Min         interface{} `json:"min,omitempty"`
    Max         interface{} `json:"max,omitempty"`
    Enum        []string    `json:"enum,omitempty"`
    Required    bool        `json:"required,omitempty"`
}
```

## Registry

### NewRegistry()

```go
func NewRegistry() *Registry
```

Creates an empty registry.

### NewRegistryWithEmbedded()

```go
func NewRegistryWithEmbedded() (*Registry, error)
```

Creates a registry preloaded with embedded capability definitions.

### Register(def *SchemeDefinition)

```go
func (r *Registry) Register(def *SchemeDefinition)
```

Registers a capability definition. Overwrites if scheme_id already exists.

### Get(schemeID string) (*SchemeDefinition, bool)

```go
func (r *Registry) Get(schemeID string) (*SchemeDefinition, bool)
```

Gets a capability definition by scheme_id.

### ValidateCapability(formatted string) (*SchemeDefinition, *CapabilityEntry, error)

```go
func (r *Registry) ValidateCapability(formatted string) (*SchemeDefinition, *CapabilityEntry, error)
```

Validates whether a capability in "vendor/product:capability_id" format is valid.

### ValidateCapabilities(caps []string) *ValidationResult

```go
func (r *Registry) ValidateCapabilities(caps []string) *ValidationResult
```

Batch-validates a capability list.

### CheckSubset(declared, allowed []string) []string

```go
func (r *Registry) CheckSubset(declared, allowed []string) []string
```

Checks whether declared is a subset of allowed. Returns over-privileged capabilities.

### SchemeIDs() []string

```go
func (r *Registry) SchemeIDs() []string
```

Returns all registered scheme_ids, sorted alphabetically.

### Summary() string

```go
func (r *Registry) Summary() string
```

Returns a human-readable summary.

## Loader

### LoadScheme(path string) (*SchemeDefinition, error)

```go
func LoadScheme(path string) (*SchemeDefinition, error)
```

Loads a single capability JSON file from disk.

### LoadFromDir(root string) (map[string]*SchemeDefinition, error)

```go
func LoadFromDir(root string) (map[string]*SchemeDefinition, error)
```

Loads all capability JSON files from a directory tree.

### LoadEmbedded() (map[string]*SchemeDefinition, error)

```go
func LoadEmbedded() (map[string]*SchemeDefinition, error)
```

Loads from embedded files.

### LoadFromBoth(diskDir string) (map[string]*SchemeDefinition, error)

```go
func LoadFromBoth(diskDir string) (map[string]*SchemeDefinition, error)
```

Embedded first, disk overrides.

## Signing

### SignCapability(certPath, keyPath, capPath, outputPath string) error

```go
func SignCapability(certPath, keyPath, capPath, outputPath string) error
```

Signs a capability JSON file with PKCS#7.

### VerifyCapabilityPKCS7(capPath string, trustRoots []*x509.Certificate) error

```go
func VerifyCapabilityPKCS7(capPath string, trustRoots []*x509.Certificate) error
```

Verifies a .p7s signature file.

### LoadTrustRoots(path string) ([]*x509.Certificate, error)

```go
func LoadTrustRoots(path string) ([]*x509.Certificate, error)
```

Loads trust root certificates from a file or directory.

### LoadCertFile(path string) ([]*x509.Certificate, error)

```go
func LoadCertFile(path string) ([]*x509.Certificate, error)
```

Reads the full certificate chain (trust root/signer chain) from a PEM file.

## GenAuthz (Generate authz.json from Specs)

### GenAuthz(cfg GenAuthzConfig) (*AuthzDocument, error)

```go
func GenAuthz(cfg GenAuthzConfig) (*AuthzDocument, error)
```

Generates an authz.json document from capability.json schemes. Mapping rules:
- Primary scheme's (the first one) Roles → authz.json roles (grants kept as-is)
- Role OUs → ou_mapping
- Namespace roles (e.g., gateway:admin, aggregated across all schemes) → gateway_namespaces
- capability parameters.default → capability_parameters (`scheme:cap_id`)

### GenAuthzToFile(cfg GenAuthzConfig, outputPath string) error

```go
func GenAuthzToFile(cfg GenAuthzConfig, outputPath string) error
```

Generates and writes the authz.json file.

### GenAuthzConfig

```go
type GenAuthzConfig struct {
    SchemePaths      []string // first is the primary scheme (provides roles)
    VerifySignature  bool     // verify signature when .p7s exists
    VerifyRequired   bool     // error directly if .p7s missing
    TrustRootsPEM    []string // trust root PEM files for verification
    Version          string   // authz.json version (default v2)
    NamespacePrefix  string   // extra gateway namespace prefix (default gateway:)
}
```

### AuthzDocument

```go
type AuthzDocument struct {
    Version              string
    Roles                map[string]AuthzRoleDef
    OUMapping            map[string]string
    GatewayNamespaces    map[string]GatewayNSDef
    CapabilityParameters map[string]map[string]any // parameter defaults
}
```

Top-level structure compatible with core/auth.Policy; `capability_parameters` is an extension field.

## GenDocs (Generate Permission Documentation from Specs)

### GenDocs(def *SchemeDefinition) (string, error)

```go
func GenDocs(def *SchemeDefinition) (string, error)
```

Generates a markdown permission document (capability catalog/detailed semantics/wildcard rules/role mapping/least-privilege guide).

### GenDocsToFile(def *SchemeDefinition, outputPath string) error

```go
func GenDocsToFile(def *SchemeDefinition, outputPath string) error
```

Generates and writes the markdown file.

## MinCapability (Least-Privilege Validation)

### CapabilityClaim

```go
type CapabilityClaim struct {
    SchemeID   string         `json:"scheme_id"`
    Capability string         `json:"capability"`
    Parameters map[string]any `json:"parameters,omitempty"`
    Rationale  string         `json:"rationale,omitempty"`
}
```

A single AI-generated capability claim.

### ParseCapabilityClaims(data []byte) ([]CapabilityClaim, error)

```go
func ParseCapabilityClaims(data []byte) ([]CapabilityClaim, error)
```

Parses a list of capability claims from JSON.

### (r *Registry) ValidateClaims(claims []CapabilityClaim) []ClaimResult

```go
func (r *Registry) ValidateClaims(claims []CapabilityClaim) []ClaimResult
```

Validates claim validity (scheme exists, capability valid, parameters defined).

### (r *Registry) CheckMinimalCapabilitySet(claims []CapabilityClaim, grantedPatterns []string) *MinSetReport

```go
func (r *Registry) CheckMinimalCapabilitySet(claims []CapabilityClaim, grantedPatterns []string) *MinSetReport
```

Least-privilege validation: validity + redundancy detection (covered by wildcards) + over-privilege detection (not authorized for the identity).

## CLI Tools

| Tool | Purpose |
|------|---------|
| `gen-authz` | Generate authz.json from capability.json (-list/-out/-verify/-verify-required/-trust-roots) |
| `gen-docs` | Generate markdown permission docs from capability.json |
| `gen-capability` | Validate AI-generated capability sets + least-privilege suggestions (-grants/-minimal) |
| `sign` | Sign capability.json producing .p7s |
| `verify` | Verify capability.json's .p7s signature |

## Helpers

### MatchCapability(id, pattern string) bool

```go
func MatchCapability(id, pattern string) bool
```

Glob-semantics wildcard matching (exact/`*`/`?`/`a:b:*` prefix). Same semantics as types.

### (def *SchemeDefinition) ValidateSchemeRoles() ([]error, []string)

```go
func (def *SchemeDefinition) ValidateSchemeRoles() ([]error, []string)
```

Validates role definitions: non-wildcard grants must be covered by this scheme's capabilities (error);
wildcard grants not matched locally are treated as cross-scheme namespace authorizations (warning).

### ParseSchemeID(schemeID string) (vendor, product string, ok bool)

```go
func ParseSchemeID(schemeID string) (vendor, product string, ok bool)
```

Parses "vendor/product".

### FormatSchemeID(vendor, product string) string

```go
func FormatSchemeID(vendor, product string) string
```

Formats into "vendor/product".

### ParseCapability(s string) (schemeID, capID string, ok bool)

```go
func ParseCapability(s string) (schemeID, capID string, ok bool)
```

Parses "vendor/product:capability_id".

### FilterByScheme(caps []string, schemeID string) []string

```go
func FilterByScheme(caps []string, schemeID string) []string
```

Filters a capability list by scheme_id.

### Deduplicate(caps []string) []string

```go
func Deduplicate(caps []string) []string
```

Deduplicates.
