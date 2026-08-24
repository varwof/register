package register

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ParameterDef defines a parameter for a capability.
type ParameterDef struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Min         interface{} `json:"min,omitempty"`
	Max         interface{} `json:"max,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Required    bool        `json:"required,omitempty"`
}

// CapabilityEntry defines a single capability within a scheme.
type CapabilityEntry struct {
	ID          string                  `json:"id"`
	Description string                  `json:"description"`
	Parameters  map[string]ParameterDef `json:"parameters,omitempty"`
	// ParamsSchema carries a JSON Schema document for structured,
	// nested capability parameters (e.g. database tables/columns/
	// row_filter). Additive: schemes using only the flat ParameterDef
	// model leave it unset.
	ParamsSchema json.RawMessage `json:"params_schema,omitempty"`
	// AI-friendly semantic description fields (used by gen-docs to generate markdown permission docs).
	// These fields help LLMs understand the exact purpose of each capability,
	// enabling them to generate minimal privilege capability sets per task.
	Summary  string   `json:"summary,omitempty"`  // One-line summary (defaults to Description)
	Usage    string   `json:"usage,omitempty"`    // When this capability is needed (typical scenarios)
	WhenNot  string   `json:"when_not,omitempty"` // When this capability should NOT be granted (avoid over-provisioning)
	Examples []string `json:"examples,omitempty"` // Typical usage examples
	Related  []string `json:"related,omitempty"`  // Related capability IDs (collaboration/alternative relationships)
}

// RoleDef defines a role within a product (used to generate authz.json).
// grants is a list of capability_id values (e.g. "ca:list", "cert:*"),
// supports wildcards (* / a:b:*); during expansion validation, all must fall within Capabilities.
type RoleDef struct {
	DisplayName string   `json:"display_name,omitempty"`
	Profiles    []string `json:"profiles,omitempty"`
	Grants      []string `json:"grants"`
	// OUs is the list of certificate OrganizationalUnits this role can be bound to.
	// When generating authz.json, written into ou_mapping; if left empty, no OU mapping entry is generated.
	OUs []string `json:"ous,omitempty"`
}

// SchemeDefinition defines all capabilities for a product.
type SchemeDefinition struct {
	SchemeID     string            `json:"scheme_id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Vendor       string            `json:"vendor"`
	Product      string            `json:"product"`
	Author       string            `json:"author,omitempty"`
	License      string            `json:"license,omitempty"`
	Homepage     string            `json:"homepage,omitempty"`
	Capabilities []CapabilityEntry `json:"capabilities"`
	// Roles defines roles within this product (grants reference capability_id from this scheme).
	// Used by gen-authz tool when generating authz.json; can be empty (pure capability catalog products).
	Roles map[string]RoleDef `json:"roles,omitempty"`
}

// ParseSchemeID parses "vendor/product" into vendor and product.
func ParseSchemeID(schemeID string) (vendor, product string, ok bool) {
	parts := strings.SplitN(schemeID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// FormatSchemeID formats vendor and product into "vendor/product".
func FormatSchemeID(vendor, product string) string {
	return vendor + "/" + product
}

// ValidateSchemeID checks if scheme_id follows the naming convention.
// Public: vendor/product (e.g., oracle/mysql, varwof/core)
// Private: x-vendor/product (e.g., x-acme/order)
func ValidateSchemeID(schemeID string) error {
	vendor, product, ok := ParseSchemeID(schemeID)
	if !ok {
		return fmt.Errorf("invalid scheme_id format: %s (expected vendor/product)", schemeID)
	}
	// vendor: lowercase alphanumeric + hyphens
	for _, c := range vendor {
		if !isAlphaHyphen(c) {
			return fmt.Errorf("invalid vendor name: %s (only lowercase letters, digits, hyphens)", vendor)
		}
	}
	// product: lowercase alphanumeric + hyphens
	for _, c := range product {
		if !isAlphaHyphen(c) {
			return fmt.Errorf("invalid product name: %s (only lowercase letters, digits, hyphens)", product)
		}
	}
	return nil
}

func isAlphaHyphen(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
}

// WriteScheme serializes a scheme definition as JSON and writes it to a file (for gen-authz tests/rewrites).
func WriteScheme(def *SchemeDefinition, path string) error {
	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scheme: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// LoadScheme reads a capability JSON file and returns the definition.
func LoadScheme(path string) (*SchemeDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var def SchemeDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if def.SchemeID == "" {
		return nil, fmt.Errorf("scheme_id is required in %s", path)
	}
	if err := ValidateSchemeID(def.SchemeID); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(def.Capabilities) == 0 {
		return nil, fmt.Errorf("at least one capability required in %s", path)
	}
	// auto-fill vendor/product from scheme_id if not set
	if def.Vendor == "" || def.Product == "" {
		v, p, _ := ParseSchemeID(def.SchemeID)
		if def.Vendor == "" {
			def.Vendor = v
		}
		if def.Product == "" {
			def.Product = p
		}
	}
	return &def, nil
}

// ValidateSchemeRoles validates the consistency of role definitions within a scheme:
//   - Role names are non-empty
//   - Role grants are non-empty
//   - Non-wildcard grants must be covered by capabilities (strict error)
//   - Wildcard grants not covered locally are treated as cross-scheme namespace authorization (e.g. core role referencing gateway:*), returning a warning
//
// Returns (errors, warnings).
func (def *SchemeDefinition) ValidateSchemeRoles() ([]error, []string) {
	var errs []error
	var warns []string
	if def == nil || len(def.Roles) == 0 {
		return nil, nil
	}
	ids := ListCapabilities(def)
	for role, rd := range def.Roles {
		if role == "" {
			errs = append(errs, fmt.Errorf("roles: empty role name"))
			continue
		}
		if len(rd.Grants) == 0 {
			errs = append(errs, fmt.Errorf("roles[%s]: grants must not be empty", role))
			continue
		}
		for _, g := range rd.Grants {
			covered := false
			for _, id := range ids {
				if MatchCapability(id, g) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			// Not covered: wildcards (containing *) are treated as cross-scheme namespace authorization, warning only.
			if strings.Contains(g, "*") {
				warns = append(warns, fmt.Sprintf("roles[%s]: grant %q not in local scheme (cross-scheme namespace wildcard)", role, g))
				continue
			}
			errs = append(errs, fmt.Errorf("roles[%s]: grant %q not covered by any capability in %s", role, g, def.SchemeID))
		}
	}
	return errs, warns
}

// LoadAllSchemes loads all capability JSON files under a directory tree.
// Expected structure: root/vendor/product/v*.json
func LoadAllSchemes(root string) (map[string]*SchemeDefinition, error) {
	schemes := make(map[string]*SchemeDefinition)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// match v*.json files
		base := filepath.Base(path)
		if !strings.HasPrefix(base, "v") || !strings.HasSuffix(base, ".json") {
			return nil
		}
		def, err := LoadScheme(path)
		if err != nil {
			return err
		}
		schemes[def.SchemeID] = def
		return nil
	})
	return schemes, err
}

// FormatCapability formats a capability as "vendor/product:capability_id".
func FormatCapability(schemeID, capID string) string {
	return schemeID + ":" + capID
}

// ParseCapability parses "vendor/product:capability_id" into scheme and capID.
// capability_id may itself contain colons (e.g., "query:users").
func ParseCapability(s string) (schemeID, capID string, ok bool) {
	// find the slash first
	slashIdx := strings.Index(s, "/")
	if slashIdx < 0 {
		return "", "", false
	}
	// find the first colon after the slash — that's the scheme/cap separator
	colonIdx := strings.Index(s[slashIdx:], ":")
	if colonIdx < 0 {
		return "", "", false
	}
	absColonIdx := slashIdx + colonIdx
	return s[:absColonIdx], s[absColonIdx+1:], true
}

// ListCapabilities returns all capability IDs for a scheme, sorted.
func ListCapabilities(def *SchemeDefinition) []string {
	ids := make([]string, 0, len(def.Capabilities))
	for _, c := range def.Capabilities {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}
