// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"encoding/json"
	"strings"

	"github.com/varwof/register/schemeadmin"
)

// Discovery is the CLC-CATALOG-DISCOVERY-v1 candidate record.  It is a pointer
// to a catalog, never a decision: a consumer must fetch the named catalog,
// verify its signature and run Verify before executing anything.
type Discovery struct {
	Version                  string   `json:"@version"`
	Provider                 string   `json:"provider"`
	CatalogID                string   `json:"catalog_id"`
	CatalogDigest            string   `json:"catalog_digest"`
	Generation               int64    `json:"generation"`
	IssuedAt                 string   `json:"issued_at"`
	ValidUntil               string   `json:"valid_until"`
	StatusReference          string   `json:"status_reference,omitempty"`
	SchemeDeclarationDigests []string `json:"scheme_declaration_digests,omitempty"`
}

// verdictMembers are member names that would assert a decision.  A discovery
// record carrying one is not a discovery record; refusal is explicit rather
// than a generic unknown-member error so the intent is visible in the reason.
var verdictMembers = []string{
	"verdict", "authorized", "authorised", "verified", "approved", "allowed", "trusted", "accepted",
}

// ParseDiscovery decodes exactly one closed discovery object and validates it.
func ParseDiscovery(raw []byte) (*Discovery, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fail(CodeDiscoveryShape, "%s", err)
	}
	for _, member := range verdictMembers {
		if _, ok := probe[member]; ok {
			return nil, fail(CodeDiscoveryVerdict, "discovery must not carry a %q member", member)
		}
	}
	var d Discovery
	if err := decodeClosed(raw, &d); err != nil {
		return nil, fail(CodeDiscoveryShape, "%s", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks the record's own shape.
func (d *Discovery) Validate() error {
	if d.Version != DiscoveryVersion {
		return fail(CodeDiscoveryShape, "@version must be %q", DiscoveryVersion)
	}
	if !nameRe.MatchString(d.CatalogID) {
		return fail(CodeDiscoveryShape, "catalog_id %q is not a catalog identity", d.CatalogID)
	}
	if d.Provider == "" {
		return fail(CodeDiscoveryShape, "provider is required")
	}
	if strings.TrimSpace(d.Provider) != d.Provider || strings.ContainsAny(d.Provider, " \t\r\n") {
		return fail(CodeDiscoveryShape, "provider %q is not an identity reference", d.Provider)
	}
	if !digestRe.MatchString(d.CatalogDigest) {
		return fail(CodeDiscoveryShape, "catalog_digest is not a sha256 digest")
	}
	if d.Generation < 1 {
		return fail(CodeDiscoveryShape, "generation must be >= 1")
	}
	issued, err := parseTime(d.IssuedAt)
	if err != nil {
		return fail(CodeDiscoveryShape, "issued_at: %s", err)
	}
	until, err := parseTime(d.ValidUntil)
	if err != nil {
		return fail(CodeDiscoveryShape, "valid_until: %s", err)
	}
	if !until.After(issued) {
		return fail(CodeDiscoveryShape, "valid_until must be after issued_at")
	}
	for _, digest := range d.SchemeDeclarationDigests {
		if !digestRe.MatchString(digest) {
			return fail(CodeDiscoveryShape, "scheme_declaration_digests contains %q", digest)
		}
	}
	return nil
}

// Match checks that a discovery record points at exactly this catalog.  It still
// returns no verdict: a match means "this is the artifact the record named".
func (d Discovery) Match(c Catalog) error {
	digest, err := c.Digest()
	if err != nil {
		return fail(CodeDiscoveryShape, "%s", err)
	}
	if d.CatalogID != c.CatalogID {
		return fail(CodeDiscoveryShape, "discovery names %q, catalog is %q", d.CatalogID, c.CatalogID)
	}
	if d.Generation != c.Generation {
		return fail(CodeDiscoveryShape, "discovery names generation %d, catalog is %d", d.Generation, c.Generation)
	}
	if d.CatalogDigest != digest {
		return fail(CodeCatalogDigest, "discovery names %s, catalog is %s", d.CatalogDigest, digest)
	}
	if len(d.SchemeDeclarationDigests) > 0 {
		declared := make(map[string]bool, len(d.SchemeDeclarationDigests))
		for _, digest := range d.SchemeDeclarationDigests {
			declared[digest] = true
		}
		for _, entry := range c.Entries {
			if !declared[entry.DeclarationDigest] {
				return fail(CodeDeclarationMismatch, "discovery does not pin declaration %s for %q", entry.DeclarationDigest, entry.Capability)
			}
		}
	}
	if len(c.Entries) > 0 {
		providerFound := false
		for _, entry := range c.Entries {
			if entry.Provider == d.Provider {
				providerFound = true
				break
			}
		}
		if !providerFound {
			return fail(CodeDiscoveryShape, "discovery provider %q is not present in the catalog entries", d.Provider)
		}
	}
	if d.ValidUntil != "" {
		until, err := parseTime(d.ValidUntil)
		if err != nil {
			return fail(CodeDiscoveryShape, "valid_until: %s", err)
		}
		catalogUntil, err := parseTime(c.ValidUntil)
		if err != nil {
			return fail(CodeDiscoveryShape, "catalog valid_until: %s", err)
		}
		if catalogUntil.After(until) {
			return fail(CodeDiscoveryShape, "discovery expires before the catalog at %s", c.ValidUntil)
		}
	}
	return nil
}

// Digest returns the content address of the discovery record.
func (d Discovery) Digest() (string, error) {
	return schemeadmin.CanonicalDigest(d)
}
