// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"crypto/x509"
	"encoding/json"
	"sort"
	"strings"

	"github.com/varwof/register/schemeadmin"
	"github.com/varwof/register/semantics"
)

// SchemePolicy pins one supported scheme to the declaration that defines its
// parameter domains.  Pinning the declaration itself (not only a digest) lets
// the deployer build the CLC-1.19 domain map without fetching anything.
type SchemePolicy struct {
	Declaration json.RawMessage `json:"declaration"`
}

// TrustPolicy is the deployer-local admission policy.  It is an input, never a
// member of a catalog artifact.
type TrustPolicy struct {
	Domain    string `json:"domain"`
	CatalogID string `json:"catalog_id"`
	// Producer, when set, pins the catalog identity to one AIC principal.
	// State continuity enforces the same binding even when it is empty.
	Producer string                  `json:"producer,omitempty"`
	Schemes  map[string]SchemePolicy `json:"schemes"`
	// MaxStalenessSeconds bounds issued_at age.  Zero disables the age check
	// (valid_until still applies).
	MaxStalenessSeconds int64 `json:"max_staleness_seconds,omitempty"`
	// MaxStatusStalenessSeconds bounds status.checked_at age.  Zero disables it.
	MaxStatusStalenessSeconds int64 `json:"max_status_staleness_seconds,omitempty"`
	// RequireStatus refuses an entry without a status reference.  Absence is
	// never treated as healthy.
	RequireStatus bool `json:"require_status,omitempty"`
	// StatusValues pins the resolved health value for each status reference.
	// When RequireStatus is set, a reference is healthy only if it maps to the
	// literal "healthy"; a bare reference/timestamp is not a health verdict.
	StatusValues map[string]string `json:"status_values,omitempty"`
	// StatusResolver, when set, obtains the current health value for a status
	// reference at verification time.  It is deployment code, not policy JSON;
	// an error or a non-healthy value fails closed.
	StatusResolver func(reference string) (string, error) `json:"-"`
	// ProviderBindings optionally binds each published provider to the catalog
	// producer principal.  A non-empty map is enforced for every entry.
	ProviderBindings map[string]string `json:"provider_bindings,omitempty"`
	ObservedAt       string            `json:"observed_at"`
}

// GenerationRecord is one entry of the local accepted-generation history.
type GenerationRecord struct {
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}

// RegistryState is the deployer's persisted view of one catalog identity.
type RegistryState struct {
	Domain     string             `json:"domain,omitempty"`
	CatalogID  string             `json:"catalog_id,omitempty"`
	Producer   string             `json:"producer,omitempty"`
	Generation int64              `json:"generation"`
	Digest     string             `json:"digest,omitempty"`
	History    []GenerationRecord `json:"history,omitempty"`
}

// ValidatePolicy checks the bootstrap configuration is usable at all.
func ValidatePolicy(p TrustPolicy) error {
	if !nameRe.MatchString(p.Domain) {
		return fail(CodeCatalogShape, "policy.domain %q is not a catalog domain", p.Domain)
	}
	if !nameRe.MatchString(p.CatalogID) {
		return fail(CodeCatalogShape, "policy.catalog_id %q is not a catalog identity", p.CatalogID)
	}
	if p.Producer != "" && !principalRe.MatchString(p.Producer) {
		return fail(CodeCatalogShape, "policy.producer %q is not a principal", p.Producer)
	}
	if len(p.Schemes) == 0 {
		return fail(CodeSchemeUnsupported, "policy supports no schemes")
	}
	for name, sp := range p.Schemes {
		if !schemeRe.MatchString(name) {
			return fail(CodeSchemeUnsupported, "policy scheme %q is not a scheme id", name)
		}
		decl, err := schemeadmin.ParseDeclaration(sp.Declaration)
		if err != nil {
			return fail(CodeDeclarationMismatch, "policy declaration for %q: %s", name, err)
		}
		if decl.Scheme != name {
			return fail(CodeDeclarationMismatch, "policy declaration for %q names %q", name, decl.Scheme)
		}
	}
	if p.MaxStalenessSeconds < 0 || p.MaxStatusStalenessSeconds < 0 {
		return fail(CodeCatalogShape, "policy staleness windows must be >= 0")
	}
	if p.RequireStatus && len(p.StatusValues) == 0 && p.StatusResolver == nil {
		return fail(CodeStatusUnavailable, "policy.require_status requires explicit status_values or a status resolver")
	}
	for reference, value := range p.StatusValues {
		if strings.TrimSpace(reference) == "" || strings.ContainsAny(reference, " \t\r\n") {
			return fail(CodeCatalogShape, "policy.status_values key %q is not a status reference", reference)
		}
		switch value {
		case "healthy", "unhealthy", "degraded", "unknown":
		default:
			return fail(CodeCatalogShape, "policy.status_values[%q] %q is not a known health value", reference, value)
		}
	}
	for provider, producer := range p.ProviderBindings {
		if strings.TrimSpace(provider) == "" || strings.ContainsAny(provider, " \t\r\n") {
			return fail(CodeCatalogShape, "policy.provider_bindings key %q is not an identity reference", provider)
		}
		if !principalRe.MatchString(producer) {
			return fail(CodeCatalogShape, "policy.provider_bindings[%q] %q is not a producer principal", provider, producer)
		}
	}
	if _, err := parseTime(p.ObservedAt); err != nil {
		return fail(CodeStale, "policy.observed_at: %s", err)
	}
	return nil
}

// declaration returns the pinned declaration for a scheme and its digest.
func (p TrustPolicy) declaration(scheme string) ([]byte, string, error) {
	sp, ok := p.Schemes[scheme]
	if !ok {
		return nil, "", fail(CodeSchemeUnsupported, "scheme %q is not supported", scheme)
	}
	if _, err := schemeadmin.ParseDeclaration(sp.Declaration); err != nil {
		return nil, "", fail(CodeDeclarationMismatch, "%s", err)
	}
	digest := DigestOfDeclaration(sp.Declaration)
	if digest == "" {
		return nil, "", fail(CodeDeclarationMismatch, "scheme %q declaration has no digest", scheme)
	}
	return sp.Declaration, digest, nil
}

// DomainMap exposes the policy-pinned CLC-1.19 domain map for one capability.
// A consumer that compares requested parameters against a published operation
// (for example an admission gate) must use the same map the catalog authority
// check used, otherwise the two readings of the same declaration can diverge.
// It returns nil (shape inference) when the declaration does not declare the
// capability.
func (p TrustPolicy) DomainMap(scheme, capability string) semantics.DomainMap {
	return p.domains(scheme, capability)
}

// domains returns the CLC-1.19 domain map for one capability, or nil (shape
// inference) when the declaration does not declare it.
func (p TrustPolicy) domains(scheme, capability string) semantics.DomainMap {
	sp, ok := p.Schemes[scheme]
	if !ok {
		return nil
	}
	decl, err := schemeadmin.ParseDeclaration(sp.Declaration)
	if err != nil {
		return nil
	}
	return decl.DomainMap(capability)
}

// Accept returns the state a deployer persists after accepting c.  History keeps
// every accepted generation exactly once, so a later snapshot can still be
// compared against it; there is no rollback path and no recovery flag.  The
// method re-checks identity, generation continuity, previous_digest and
// producer so a caller cannot bypass Verify's generation rules by calling
// Accept directly.
func (s RegistryState) Accept(c Catalog, res Result) (RegistryState, error) {
	if !res.signatureVerified || res.Verdict != VerdictAccept {
		return s, fail(CodeStateUnverified, "state can only be advanced from a VerifySigned accept result")
	}
	if err := c.Validate(); err != nil {
		return s, err
	}
	if s.Domain != "" && s.Domain != c.Domain {
		return s, fail(CodeIdentityMismatch, "state domain %q is not the catalog domain %q", s.Domain, c.Domain)
	}
	if s.CatalogID != "" && s.CatalogID != c.CatalogID {
		return s, fail(CodeIdentityMismatch, "state catalog_id %q is not %q", s.CatalogID, c.CatalogID)
	}
	if s.Producer != "" && s.Producer != c.Producer {
		return s, fail(CodeIdentityMismatch, "state producer %q is not the catalog producer %q", s.Producer, c.Producer)
	}
	digest, err := c.Digest()
	if err != nil {
		return s, err
	}
	if res.CatalogDigest != digest || res.Generation != c.Generation || res.Producer != c.Producer {
		return s, fail(CodeStateUnverified, "verification result does not bind this catalog")
	}

	if s.Generation == 0 {
		if len(s.History) != 0 || s.Digest != "" {
			return s, fail(CodeFork, "empty state has history or a digest")
		}
		if c.Generation != 1 {
			return s, fail(CodeBootstrap, "no accepted generation; the first catalog must be generation 1, got %d", c.Generation)
		}
	} else if c.Generation < s.Generation {
		return s, fail(CodeRollback, "generation %d is older than the accepted %d", c.Generation, s.Generation)
	} else if c.Generation == s.Generation {
		if digest != s.Digest {
			return s, fail(CodeFork, "generation %d holds %s, not %s", c.Generation, s.Digest, digest)
		}
		return s, nil
	} else {
		if c.Generation != s.Generation+1 {
			return s, fail(CodeRollback, "generation %d skips %d", c.Generation, s.Generation+1)
		}
		if c.PreviousDigest != s.Digest {
			return s, fail(CodePreviousDigest, "previous_digest %q is not the accepted %q", c.PreviousDigest, s.Digest)
		}
	}
	if recorded := digestAt(s, c.Generation); recorded != "" && recorded != digest {
		return s, fail(CodeFork, "generation %d already holds %s", c.Generation, recorded)
	}

	next := RegistryState{
		Domain:     c.Domain,
		CatalogID:  c.CatalogID,
		Producer:   c.Producer,
		Generation: c.Generation,
		Digest:     digest,
	}
	seen := map[int64]bool{}
	history := make([]GenerationRecord, 0, len(s.History)+1)
	add := func(generation int64, record string) {
		if generation == 0 || seen[generation] {
			return
		}
		seen[generation] = true
		history = append(history, GenerationRecord{Generation: generation, Digest: record})
	}
	add(c.Generation, digest)
	for _, record := range s.History {
		add(record.Generation, record.Digest)
	}
	add(s.Generation, s.Digest)
	sort.Slice(history, func(i, j int) bool { return history[i].Generation < history[j].Generation })
	next.History = history
	return next, nil
}

// AcceptSigned verifies a detached catalogue signature and only then advances
// the state.  This is the safe state-writer entry point; Accept alone requires
// the resulting signed marker and is intended for callers that already ran
// VerifySigned.
func (s RegistryState) AcceptSigned(raw, signature []byte, roots []*x509.Certificate, policy TrustPolicy) (RegistryState, Result, error) {
	res, err := VerifySigned(raw, signature, roots, policy, s)
	if err != nil {
		return s, res, err
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return s, res, err
	}
	next, err := s.Accept(*c, res)
	return next, res, err
}
