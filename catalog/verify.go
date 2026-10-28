// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	pki "github.com/varwof/types"

	"github.com/varwof/register/schemeadmin"
	"github.com/varwof/register/semantics"
)

// clockSkew is the tolerated forward error for artifact timestamps.
const clockSkew = 5 * time.Minute

// Verdicts.  A consumer persists a snapshot only on VerdictAccept.
const (
	VerdictAccept = "accept"
	VerdictReject = "reject"
)

// Verification is one deployer check: the artifact plus every local input the
// decision depends on.
type Verification struct {
	Catalog    Catalog
	SignerCert *x509.Certificate
	Roots      []*x509.Certificate
	Policy     TrustPolicy
	State      RegistryState
}

// Result is the replayable decision record.  It binds the artifact, the signer,
// the policy, the prior state and the recomputed verdict; it never carries a
// bare trust boolean.
type Result struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Domain     string `json:"domain"`
	CatalogID  string `json:"catalog_id"`
	Producer   string `json:"producer,omitempty"`
	Generation int64  `json:"generation"`

	CatalogDigest string `json:"catalog_digest,omitempty"`
	SignerKeyID   string `json:"signer_key_id,omitempty"`
	// SignerCertificateDigest binds the exact certificate (validity/AIC
	// container) and AICDigest binds the raw AIC extension value, so a reissued
	// certificate with the same key is visible in the decision record.
	SignerCertificateDigest string `json:"signer_certificate_digest,omitempty"`
	AICDigest               string `json:"aic_digest,omitempty"`
	PolicyDigest            string `json:"policy_digest,omitempty"`
	StateDigest             string `json:"state_digest,omitempty"`
	InputsDigest            string `json:"inputs_digest,omitempty"`

	// signatureVerified is set only by VerifySigned after the detached
	// signature over the exact raw catalog verified.  State writers require it.
	signatureVerified bool

	// deltaVerified is set only by VerifySignedDelta* after the detached
	// signature over the delta verified and the delta was applied to a base
	// whose digest the result binds.  AcceptDelta requires it, because a delta
	// signature is not a catalogue signature and must not be able to reuse
	// signatureVerified.
	deltaVerified bool
}

// Verify is retained only as a fail-closed compatibility stub.  Use
// VerifySigned: it verifies the detached signature over the exact bytes before
// parsing or admitting the catalogue.
func Verify(v Verification) (Result, error) {
	res := Result{
		Verdict:    VerdictReject,
		Domain:     v.Catalog.Domain,
		CatalogID:  v.Catalog.CatalogID,
		Producer:   v.Catalog.Producer,
		Generation: v.Catalog.Generation,
	}
	err := fail(CodeSignatureMissing, "Verify does not verify signatures; use VerifySigned")
	res.Reason = CodeOf(err)
	res.Detail = detailOf(err)
	return res, err
}

// verify runs the deployer admission algorithm for a caller that has already
// verified the detached signature and recovered the signer certificate.
func verify(v Verification) (Result, error) {
	res := Result{
		Verdict:    VerdictReject,
		Domain:     v.Catalog.Domain,
		CatalogID:  v.Catalog.CatalogID,
		Producer:   v.Catalog.Producer,
		Generation: v.Catalog.Generation,
	}
	if d, err := v.Catalog.Digest(); err == nil {
		res.CatalogDigest = d
	}
	if v.SignerCert != nil {
		res.SignerKeyID = KeyID(v.SignerCert)
		res.SignerCertificateDigest = schemeadmin.Digest(v.SignerCert.Raw)
		res.AICDigest = aicExtensionDigest(v.SignerCert)
	}
	if d, err := schemeadmin.CanonicalDigest(v.Policy); err == nil {
		res.PolicyDigest = d
	}
	if d, err := schemeadmin.CanonicalDigest(v.State); err == nil {
		res.StateDigest = d
	}
	if d, err := schemeadmin.CanonicalDigest(map[string]string{
		"catalog":            res.CatalogDigest,
		"signer":             res.SignerKeyID,
		"signer_certificate": res.SignerCertificateDigest,
		"aic":                res.AICDigest,
		"policy":             res.PolicyDigest,
		"state":              res.StateDigest,
	}); err == nil {
		res.InputsDigest = d
	}

	if err := decide(v, res.CatalogDigest); err != nil {
		res.Reason = CodeOf(err)
		res.Detail = detailOf(err)
		return res, err
	}
	res.Verdict = VerdictAccept
	return res, nil
}

func decide(v Verification, catalogDigest string) error {
	if err := ValidatePolicy(v.Policy); err != nil {
		return err
	}
	if err := v.Catalog.Validate(); err != nil {
		return err
	}
	if v.Catalog.Domain != v.Policy.Domain {
		return fail(CodeIdentityMismatch, "catalog domain %q is not the policy domain %q", v.Catalog.Domain, v.Policy.Domain)
	}
	if v.Catalog.CatalogID != v.Policy.CatalogID {
		return fail(CodeIdentityMismatch, "catalog_id %q is not the policy catalog %q", v.Catalog.CatalogID, v.Policy.CatalogID)
	}
	if v.Policy.Producer != "" && v.Catalog.Producer != v.Policy.Producer {
		return fail(CodeIdentityMismatch, "producer %q is not the policy producer %q", v.Catalog.Producer, v.Policy.Producer)
	}

	now, err := parseTime(v.Policy.ObservedAt)
	if err != nil {
		return fail(CodeStale, "policy.observed_at: %s", err)
	}
	aic, err := verifySigner(v.Catalog, v.SignerCert, v.Roots, now)
	if err != nil {
		return err
	}

	if err := checkDeclarationPins(v.Catalog, v.Policy); err != nil {
		return err
	}
	if err := checkProviderBindings(v.Catalog, v.Policy); err != nil {
		return err
	}
	if err := checkGeneration(v.Catalog, v.State, catalogDigest); err != nil {
		return err
	}
	if err := checkFreshness(v.Catalog, v.Policy); err != nil {
		return err
	}
	if err := checkStatus(v.Catalog, v.Policy); err != nil {
		return err
	}
	if err := checkAuthority(v.Catalog, v.Policy, aic); err != nil {
		return err
	}
	return nil
}

// checkDeclarationPins verifies every entry's scheme is supported and pins the
// policy declaration exactly.  It is shared by full Verify and by the delta
// path, which must recheck the complete resulting catalogue rather than only
// the entries the delta touched.
func checkDeclarationPins(c Catalog, p TrustPolicy) error {
	for _, entry := range c.Entries {
		_, digest, err := p.declaration(entry.Scheme)
		if err != nil {
			return err
		}
		if entry.DeclarationDigest != digest {
			return fail(CodeDeclarationMismatch,
				"entry %q pins %s, policy pins %s", entry.Capability, entry.DeclarationDigest, digest)
		}
	}
	return nil
}

// verifySigner re-checks the chain and the AIC binding.  The caller is expected
// to have verified the detached signature; this is the independent second check.
func verifySigner(c Catalog, cert *x509.Certificate, roots []*x509.Certificate, now time.Time) (*pki.AIC, error) {
	if cert == nil {
		return nil, fail(CodeSignatureMissing, "signer certificate is required")
	}
	if len(roots) == 0 {
		return nil, fail(CodeSignatureChain, "no trust roots configured")
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		if r != nil {
			pool.AddCert(r)
		}
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fail(CodeSignatureChain, "signer certificate key usage does not permit digital signatures")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: now,
	}); err != nil {
		return nil, fail(CodeSignatureChain, "%s", err)
	}

	aic, err := pki.ParseAIC(cert)
	if err != nil {
		return nil, fail(CodeSignatureNoAIC, "%s", err)
	}
	if aic == nil {
		return nil, fail(CodeSignatureNoAIC, "signer certificate carries no AIC extension")
	}
	if err := pki.ValidateAIC(aic); err != nil {
		return nil, fail(CodeSignatureNoAIC, "signer AIC is invalid: %s", err)
	}

	want := strings.TrimPrefix(c.Producer, "principal:")
	id := aic.PrincipalUid.Identifier
	realm := aic.PrincipalUid.Realm
	if want != id && want != realm+":"+id {
		return nil, fail(CodePublisherMismatch, "catalog names %q, AIC names %q", c.Producer, realm+":"+id)
	}
	if len(aic.PrincipalUid.KeyHash) == 0 || allZero(aic.PrincipalUid.KeyHash) {
		return nil, fail(CodePublisherKeyBinding, "AIC carries no principal key hash")
	}
	if !bytes.Equal(aic.PrincipalUid.KeyHash, keyHash(cert)) {
		return nil, fail(CodePublisherKeyBinding, "AIC key hash does not match the certificate key")
	}
	return aic, nil
}

func checkGeneration(c Catalog, state RegistryState, digest string) error {
	if state.Domain != "" && state.Domain != c.Domain {
		return fail(CodeIdentityMismatch, "state domain %q is not the catalog domain %q", state.Domain, c.Domain)
	}
	if state.CatalogID != "" && state.CatalogID != c.CatalogID {
		return fail(CodeIdentityMismatch, "state catalog_id %q is not %q", state.CatalogID, c.CatalogID)
	}
	if state.Producer != "" && state.Producer != c.Producer {
		return fail(CodeIdentityMismatch, "state producer %q is not the catalog producer %q", state.Producer, c.Producer)
	}

	if state.Generation == 0 {
		if c.Generation != 1 {
			return fail(CodeBootstrap, "no accepted generation; the first catalog must be generation 1, got %d", c.Generation)
		}
		return nil
	}

	if recorded := digestAt(state, c.Generation); recorded != "" && recorded != digest {
		return fail(CodeFork, "generation %d already holds %s", c.Generation, recorded)
	}
	if c.Generation < state.Generation {
		return fail(CodeRollback, "generation %d is older than the accepted %d", c.Generation, state.Generation)
	}
	if c.Generation == state.Generation {
		if digest != state.Digest {
			return fail(CodeFork, "generation %d holds %s, not %s", c.Generation, state.Digest, digest)
		}
		return nil
	}
	if c.Generation != state.Generation+1 {
		return fail(CodeRollback, "generation %d skips %d", c.Generation, state.Generation+1)
	}
	if c.PreviousDigest != state.Digest {
		return fail(CodePreviousDigest, "previous_digest %q is not the accepted %q", c.PreviousDigest, state.Digest)
	}
	return nil
}

func checkFreshness(c Catalog, p TrustPolicy) error {
	now, err := parseTime(p.ObservedAt)
	if err != nil {
		return fail(CodeStale, "policy.observed_at: %s", err)
	}
	until, err := parseTime(c.ValidUntil)
	if err != nil {
		return fail(CodeCatalogShape, "valid_until: %s", err)
	}
	issued, err := parseTime(c.IssuedAt)
	if err != nil {
		return fail(CodeCatalogShape, "issued_at: %s", err)
	}
	if issued.After(now.Add(clockSkew)) {
		return fail(CodeStale, "issued_at %s is in the future of observed_at %s", c.IssuedAt, p.ObservedAt)
	}
	if !until.After(issued) {
		return fail(CodeCatalogShape, "valid_until %s is not after issued_at %s", c.ValidUntil, c.IssuedAt)
	}
	if now.After(until) {
		return fail(CodeExpired, "valid_until %s precedes observed_at %s", c.ValidUntil, p.ObservedAt)
	}
	if p.MaxStalenessSeconds > 0 && now.Sub(issued) > seconds(p.MaxStalenessSeconds) {
		return fail(CodeStale, "catalog is older than %ds", p.MaxStalenessSeconds)
	}
	return nil
}

func checkStatus(c Catalog, p TrustPolicy) error {
	now, err := parseTime(p.ObservedAt)
	if err != nil {
		return fail(CodeStale, "policy.observed_at: %s", err)
	}
	for _, entry := range c.Entries {
		if entry.Status == nil {
			if p.RequireStatus {
				return fail(CodeStatusUnavailable, "entry %q has no status reference", entry.Capability)
			}
			continue
		}
		checked, err := parseTime(entry.Status.CheckedAt)
		if err != nil {
			return fail(CodeCatalogShape, "entry %q status.checked_at: %s", entry.Capability, err)
		}
		if checked.After(now) {
			return fail(CodeStatusStale, "entry %q status is checked in the future", entry.Capability)
		}
		if p.MaxStatusStalenessSeconds > 0 && now.Sub(checked) > seconds(p.MaxStatusStalenessSeconds) {
			return fail(CodeStatusStale, "entry %q status is older than %ds", entry.Capability, p.MaxStatusStalenessSeconds)
		}
		if p.RequireStatus {
			value, ok := p.StatusValues[entry.Status.Reference]
			if p.StatusResolver != nil {
				resolved, err := p.StatusResolver(entry.Status.Reference)
				if err != nil {
					return fail(CodeStatusUnavailable, "entry %q status resolver: %s", entry.Capability, err)
				}
				if resolved != "" {
					value, ok = resolved, true
				}
			}
			if !ok {
				return fail(CodeStatusUnavailable, "entry %q status reference %q has no resolved value", entry.Capability, entry.Status.Reference)
			}
			if value != "healthy" {
				return fail(CodeStatusUnavailable, "entry %q status %q is %s", entry.Capability, entry.Status.Reference, value)
			}
		}
	}
	return nil
}

// checkProviderBindings enforces the optional deployer-local provider →
// producer map.  The catalog's provider field is an attribution reference; it
// is only trusted when the policy explicitly binds it to the catalog producer.
func checkProviderBindings(c Catalog, p TrustPolicy) error {
	if len(p.ProviderBindings) == 0 {
		return nil
	}
	for _, entry := range c.Entries {
		producer, ok := p.ProviderBindings[entry.Provider]
		if !ok {
			return fail(CodeProviderMismatch, "entry %q provider %q has no policy binding", entry.Capability, entry.Provider)
		}
		if producer != c.Producer {
			return fail(CodeProviderMismatch, "entry %q provider %q is bound to producer %q, catalog producer is %q", entry.Capability, entry.Provider, producer, c.Producer)
		}
	}
	return nil
}

// checkAuthority is the publication boundary: every published operation must be
// inside the signer's own AIC grant for that exact capability.
func checkAuthority(c Catalog, p TrustPolicy, aic *pki.AIC) error {
	for _, entry := range c.Entries {
		grants := grantsFor(aic, entry.Capability)
		if len(grants) == 0 {
			return fail(CodeEntryOutsideAuthority, "signer holds no grant for %q", entry.Capability)
		}
		dm := p.domains(entry.Scheme, capabilityOf(entry))
		for _, op := range entry.Operations {
			covered := false
			for _, g := range grants {
				if res := semantics.ContainsWithDomains(g, op.Grant(entry.Capability), dm, dm); res.Contains {
					covered = true
					break
				}
			}
			if !covered {
				return fail(CodeEntryOutsideAuthority,
					"entry %q operation %q exceeds the signer grant", entry.Capability, op.Operation)
			}
		}
	}
	return nil
}

func grantsFor(aic *pki.AIC, fullID string) []semantics.Grant {
	if aic == nil {
		return nil
	}
	out := make([]semantics.Grant, 0, len(aic.Capabilities))
	for _, cap := range aic.Capabilities {
		if !coversGrantID(cap.FullID(), fullID) {
			continue
		}
		g, ok := grantFromAICCapability(cap)
		if !ok {
			continue
		}
		out = append(out, g)
	}
	return out
}

func coversGrantID(grantID, opID string) bool {
	if grantID == opID {
		return true
	}
	if strings.HasSuffix(grantID, ":*") {
		prefix := strings.TrimSuffix(grantID, "*")
		return len(opID) > len(prefix) && strings.HasPrefix(opID, prefix)
	}
	return false
}

func grantFromAICCapability(cap pki.Capability) (semantics.Grant, bool) {
	g := semantics.Grant{ID: cap.FullID()}
	if len(cap.Parameters) == 0 {
		return g, true
	}
	var raw map[string]any
	if err := json.Unmarshal(cap.Parameters, &raw); err != nil {
		return semantics.Grant{}, false
	}
	params, hasParams := raw["params"].(map[string]any)
	bounds, hasBounds := raw["param_bounds"].(map[string]any)
	if _, present := raw["params"]; present && !hasParams {
		return semantics.Grant{}, false
	}
	if _, present := raw["param_bounds"]; present && !hasBounds {
		return semantics.Grant{}, false
	}
	if hasParams || hasBounds {
		g.Params = params
		g.ParamBounds = bounds
		return g, true
	}
	g.Params = raw
	return g, true
}

func capabilityOf(e Entry) string {
	return strings.TrimPrefix(e.Capability, e.Scheme+":")
}

func digestAt(state RegistryState, generation int64) string {
	if state.Generation == generation {
		return state.Digest
	}
	for _, record := range state.History {
		if record.Generation == generation {
			return record.Digest
		}
	}
	return ""
}

func keyHash(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// aicExtensionDigest binds the raw AIC extension bytes, if present.
func aicExtensionDigest(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(pki.OIDAIC) {
			return schemeadmin.Digest(ext.Value)
		}
	}
	return ""
}

func detailOf(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Detail
	}
	return err.Error()
}
