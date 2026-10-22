// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"crypto/x509"
	"time"
)

// TrustRotation is the catalog trust-anchor overlap profile.  Current roots are
// always accepted before OverlapUntil; during the overlap both current and next
// roots are accepted; after it only the next set is accepted, so an old anchor
// cannot silently remain trusted after the transition.
type TrustRotation struct {
	Current      []*x509.Certificate
	Next         []*x509.Certificate
	OverlapUntil time.Time
	RevokedKeys  map[string]bool
}

// Validate checks the rotation shape.  A next set without a finite overlap
// deadline is rejected: "rotate forever" would make the old key impossible to
// retire.
func (r TrustRotation) Validate() error {
	if len(r.Current) == 0 && len(r.Next) == 0 {
		return fail(CodeSignatureChain, "trust rotation has no roots")
	}
	if len(r.Next) > 0 && r.OverlapUntil.IsZero() {
		return fail(CodeSignatureChain, "trust rotation with next roots requires overlap_until")
	}
	return nil
}

// RootsAt returns the roots accepted at now.
func (r TrustRotation) RootsAt(now time.Time) ([]*x509.Certificate, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if len(r.Next) == 0 {
		return append([]*x509.Certificate(nil), r.Current...), nil
	}
	if now.Before(r.OverlapUntil) {
		out := make([]*x509.Certificate, 0, len(r.Current)+len(r.Next))
		out = append(out, r.Current...)
		out = append(out, r.Next...)
		return out, nil
	}
	return append([]*x509.Certificate(nil), r.Next...), nil
}

// VerifySigned verifies a catalog under the rotation window and rejects a
// signer key explicitly revoked by the profile.  The returned catalog is the
// parsed artifact, not a re-serialization.
func (r TrustRotation) VerifySigned(raw, signature []byte, policy TrustPolicy, state RegistryState) (Result, *Catalog, error) {
	now, err := parseTime(policy.ObservedAt)
	if err != nil {
		return Result{Verdict: VerdictReject, Reason: CodeStale}, nil, fail(CodeStale, "policy.observed_at: %s", err)
	}
	roots, err := r.RootsAt(now)
	if err != nil {
		return Result{Verdict: VerdictReject, Reason: CodeOf(err)}, nil, err
	}
	res, err := VerifySigned(raw, signature, roots, policy, state)
	if err != nil {
		return res, nil, err
	}
	if r.RevokedKeys != nil && r.RevokedKeys[res.SignerKeyID] {
		err := fail(CodeKeyRevoked, "catalog signer key %s is revoked", res.SignerKeyID)
		res.Verdict = VerdictReject
		res.Reason = CodeOf(err)
		return res, nil, err
	}
	cat, err := ParseCatalog(raw)
	if err != nil {
		return res, nil, err
	}
	return res, cat, nil
}
