// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"crypto/x509"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/schemeadmin"
)

// VerifySignedDelta verifies a detached signature over the exact delta bytes
// before parsing, binds the signer to the delta producer, requires the delta to
// continue the base producer and identity, checks freshness, pins every
// affected scheme declaration, checks each added/replaced entry against the
// signer's authority, and only then applies the delta.
//
// Apply alone is a pure transformation and must not be used on untrusted
// bytes; the CLI and any consumer that persists a next catalog should use this
// function.
func VerifySignedDelta(raw, signature []byte, base Catalog, roots []*x509.Certificate, policy TrustPolicy) (Result, *Catalog, error) {
	res := Result{Verdict: VerdictReject, Domain: base.Domain, CatalogID: base.CatalogID, Producer: base.Producer, Generation: base.Generation}
	if len(raw) > maxArtifactBytes {
		err := fail(CodeCatalogShape, "artifact is %d bytes, limit is %d", len(raw), maxArtifactBytes)
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	signer, err := pkcs7.VerifyDetached(signature, raw)
	if err != nil {
		res.Reason = CodeSignatureInvalid
		return res, nil, fail(CodeSignatureInvalid, "%s", err)
	}
	d, err := ParseDelta(raw)
	if err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	res.Domain = d.Domain
	res.CatalogID = d.CatalogID
	res.Producer = d.Producer
	res.Generation = d.TargetGeneration
	if signer != nil {
		res.SignerKeyID = KeyID(signer)
		res.SignerCertificateDigest = schemeadmin.Digest(signer.Raw)
		res.AICDigest = aicExtensionDigest(signer)
	}
	if err := ValidatePolicy(policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if d, err := schemeadmin.CanonicalDigest(policy); err == nil {
		res.PolicyDigest = d
	}
	if err := base.Validate(); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if d.Domain != base.Domain || d.CatalogID != base.CatalogID {
		err := fail(CodeDeltaBase, "delta is for %s/%s, base is %s/%s", d.Domain, d.CatalogID, base.Domain, base.CatalogID)
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if d.Domain != policy.Domain || d.CatalogID != policy.CatalogID {
		err := fail(CodeIdentityMismatch, "delta is for %s/%s, policy is %s/%s", d.Domain, d.CatalogID, policy.Domain, policy.CatalogID)
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if d.Producer != base.Producer {
		err := fail(CodeDeltaBase, "delta producer %q, base producer %q", d.Producer, base.Producer)
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if policy.Producer != "" && d.Producer != policy.Producer {
		err := fail(CodeIdentityMismatch, "delta producer %q is not the policy producer %q", d.Producer, policy.Producer)
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if err := checkDeltaFreshness(*d, policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}

	now, err := parseTime(policy.ObservedAt)
	if err != nil {
		res.Reason = CodeStale
		return res, nil, fail(CodeStale, "policy.observed_at: %s", err)
	}
	aic, err := verifySigner(Catalog{Producer: d.Producer}, signer, roots, now)
	if err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}

	affected := make([]Entry, 0, len(d.Add)+len(d.Replace))
	affected = append(affected, d.Add...)
	affected = append(affected, d.Replace...)
	for _, entry := range affected {
		_, digest, err := policy.declaration(entry.Scheme)
		if err != nil {
			res.Reason = CodeOf(err)
			return res, nil, err
		}
		if entry.DeclarationDigest != digest {
			err := fail(CodeDeclarationMismatch, "entry %q pins %s, policy pins %s", entry.Capability, entry.DeclarationDigest, digest)
			res.Reason = CodeOf(err)
			return res, nil, err
		}
	}
	if err := checkAuthority(Catalog{Entries: affected}, policy, aic); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}

	next, err := Apply(base, *d)
	if err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	// A delta is not a trust shortcut for the catalogue it produces.  Recheck
	// the complete next catalogue, including untouched entries: a policy may
	// have removed a scheme or tightened status/declaration requirements since
	// the base was accepted.
	if err := checkDeclarationPins(*next, policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if err := checkProviderBindings(*next, policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if err := checkFreshness(*next, policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if err := checkStatus(*next, policy); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	if err := checkAuthority(*next, policy, aic); err != nil {
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	digest, err := next.Digest()
	if err != nil {
		res.Reason = CodeDeltaDigest
		return res, nil, err
	}
	res.CatalogDigest = digest
	res.Generation = next.Generation
	baseDigest, _ := base.Digest()
	deltaDigest, err := d.Digest()
	if err != nil {
		return res, nil, err
	}
	if dg, err := schemeadmin.CanonicalDigest(map[string]string{
		"catalog": res.CatalogDigest,
		"base":    baseDigest,
		"delta":   deltaDigest,
		"signer":  res.SignerKeyID,
		"policy":  res.PolicyDigest,
	}); err == nil {
		res.InputsDigest = dg
	}
	res.Verdict = VerdictAccept
	return res, next, nil
}

// VerifySignedDeltaWithState is the CLI-facing variant: it first requires the
// supplied base catalogue to be the accepted head in state, so a signed delta
// cannot be applied to an older but valid snapshot and written as a fork.
func VerifySignedDeltaWithState(raw, signature []byte, base Catalog, roots []*x509.Certificate, policy TrustPolicy, state RegistryState) (Result, *Catalog, error) {
	if state.Generation == 0 {
		err := fail(CodeBootstrap, "apply-catalog-delta requires an accepted state head")
		return Result{Verdict: VerdictReject, Reason: CodeOf(err)}, nil, err
	}
	baseDigest, err := base.Digest()
	if err != nil {
		return Result{Verdict: VerdictReject, Reason: CodeCatalogShape}, nil, err
	}
	if state.Domain != "" && state.Domain != base.Domain {
		err := fail(CodeIdentityMismatch, "state domain %q is not the base domain %q", state.Domain, base.Domain)
		return Result{Verdict: VerdictReject, Reason: CodeOf(err)}, nil, err
	}
	if state.CatalogID != "" && state.CatalogID != base.CatalogID {
		err := fail(CodeIdentityMismatch, "state catalog_id %q is not the base catalog_id %q", state.CatalogID, base.CatalogID)
		return Result{Verdict: VerdictReject, Reason: CodeOf(err)}, nil, err
	}
	if state.Generation != base.Generation || state.Digest != baseDigest {
		err := fail(CodeRollback, "base generation %d/%s is not the accepted head %d/%s", base.Generation, baseDigest, state.Generation, state.Digest)
		return Result{Verdict: VerdictReject, Reason: CodeOf(err)}, nil, err
	}
	return VerifySignedDelta(raw, signature, base, roots, policy)
}

func checkDeltaFreshness(d Delta, p TrustPolicy) error {
	now, err := parseTime(p.ObservedAt)
	if err != nil {
		return fail(CodeStale, "policy.observed_at: %s", err)
	}
	issued, err := parseTime(d.IssuedAt)
	if err != nil {
		return fail(CodeDeltaShape, "issued_at: %s", err)
	}
	until, err := parseTime(d.ValidUntil)
	if err != nil {
		return fail(CodeDeltaShape, "valid_until: %s", err)
	}
	if issued.After(now.Add(clockSkew)) {
		return fail(CodeStale, "delta issued_at %s is in the future", d.IssuedAt)
	}
	if now.After(until) {
		return fail(CodeExpired, "delta valid_until %s precedes observed_at", d.ValidUntil)
	}
	if p.MaxStalenessSeconds > 0 && now.Sub(issued) > seconds(p.MaxStalenessSeconds) {
		return fail(CodeStale, "delta is older than %ds", p.MaxStalenessSeconds)
	}
	return nil
}
