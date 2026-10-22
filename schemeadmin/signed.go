// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"crypto/x509"
	"time"

	"github.com/varwof/pkcs7"
)

// SignedConfirmation is the complete input for a deployer decision that
// verifies the detached PKCS#7 signatures itself.  PackageBytes and
// TransitionBytes must be the exact bytes that were signed; Signatures and
// TransitionSignatures are detached PKCS#7 values over those bytes.
type SignedConfirmation struct {
	PackageBytes         []byte
	Signatures           [][]byte
	TransitionBytes      []byte
	TransitionSignatures [][]byte

	Definition  []byte
	Declaration []byte

	Roots  []*x509.Certificate
	State  RegistryState
	Policy TrustPolicy
}

// ConfirmSigned verifies every detached signature over the exact package and
// transition bytes before parsing either artifact, verifies every signer
// certificate against Roots, selects the publisher candidate whose AIC binds
// the package publisher and whose key signed the transition, and then runs the
// normal confirmation path.  For a root rotation, checkRootRotation counts the
// distinct current-root keys among the verified package signers and enforces
// policy.root_threshold.
func ConfirmSigned(c SignedConfirmation) (res ConfirmationResult, err error) {
	res = ConfirmationResult{Verdict: VerdictReject}
	defer func() {
		if err != nil && res.Reason == "" {
			res.Reason = CodeOf(err)
			if res.Reason == "" {
				res.Reason = "internal"
			}
		}
	}()
	if len(c.PackageBytes) == 0 || len(c.TransitionBytes) == 0 {
		return res, fail(CodePackageShape, "package and transition bytes are required")
	}
	if len(c.PackageBytes) > maxArtifactBytes || len(c.TransitionBytes) > maxArtifactBytes {
		return res, fail(CodePackageShape, "artifact exceeds the %d-byte limit", maxArtifactBytes)
	}
	if len(c.Signatures) == 0 {
		return res, fail(CodeSignatureMissing, "at least one detached package signature is required")
	}
	if len(c.Signatures) > maxDetachedSignatures || len(c.TransitionSignatures) > maxDetachedSignatures {
		return res, fail(CodeSignatureInvalid, "too many detached signatures (limit %d)", maxDetachedSignatures)
	}
	if len(c.TransitionSignatures) == 0 {
		return res, fail(CodeTransitionSignatureMissing, "a detached transition signature is required")
	}
	now, err := policyTime(c.Policy)
	if err != nil {
		return res, err
	}

	// Verify signatures over the exact bytes before parsing either artifact.
	signers := make([]*x509.Certificate, 0, len(c.Signatures))
	for i, sig := range c.Signatures {
		cert, err := pkcs7.VerifyDetached(sig, c.PackageBytes)
		if err != nil {
			return res, fail(CodeSignatureInvalid, "package signature %d: %s", i, err)
		}
		if cert == nil {
			return res, fail(CodeSignatureInvalid, "package signature %d recovered no certificate", i)
		}
		signers = append(signers, cert)
	}
	transitionCerts := make([]*x509.Certificate, 0, len(c.TransitionSignatures))
	for i, sig := range c.TransitionSignatures {
		cert, err := pkcs7.VerifyDetached(sig, c.TransitionBytes)
		if err != nil {
			return res, fail(CodeTransitionSignatureInvalid, "transition signature %d: %s", i, err)
		}
		if cert == nil {
			return res, fail(CodeTransitionSignatureInvalid, "transition signature %d recovered no certificate", i)
		}
		transitionCerts = append(transitionCerts, cert)
	}

	pkg, err := ParsePackage(c.PackageBytes)
	if err != nil {
		return res, err
	}
	for i, cert := range signers {
		if err := verifyChain(cert, c.Roots, now); err != nil {
			return res, fail(CodeSignatureChain, "package signer %d: %s", i, err)
		}
	}
	for i, cert := range transitionCerts {
		if err := verifyChain(cert, c.Roots, now); err != nil {
			return res, fail(CodeSignatureChain, "transition signer %d: %s", i, err)
		}
	}

	tr, err := ParseTransition(c.TransitionBytes)
	if err != nil {
		return res, err
	}

	// The result is populated only after both signed artifacts parsed, so a
	// pre-parse shape error does not look like a partially trusted decision.
	res.Scheme = pkg.Scheme
	res.Generation = pkg.Generation
	if d, err := PackageDigest(pkg); err == nil {
		res.PackageDigest = d
	}
	if len(signers) > 0 {
		res.PublisherKeyID = KeyID(signers[0])
	}
	res.Action = tr.Action
	res.Namespace = tr.Namespace
	if d, err := TransitionDigest(tr); err == nil {
		res.TransitionDigest = d
	}
	if op, err := BuildManagementOperation(pkg, tr); err == nil {
		res.ManagementOperationDigest, _ = OperationDigest(op)
	}

	// A publisher candidate must bind package.publisher through its AIC.  Keep
	// all of them: a principal-matching co-signer without the operation grant
	// must not shadow a candidate that has it.
	candidates := make([]*x509.Certificate, 0, len(signers))
	publisherKeys := make(map[string]bool, len(signers))
	var lastErr error
	for _, cert := range signers {
		if _, err := verifyPublisher(pkg, cert, c.Roots, now); err == nil {
			candidates = append(candidates, cert)
			publisherKeys[keyIDOf(cert.RawSubjectPublicKeyInfo)] = true
		} else {
			lastErr = err
		}
	}
	if len(candidates) == 0 {
		if lastErr != nil {
			return res, lastErr
		}
		return res, fail(CodePublisherMismatch, "no verified signature binds package publisher %q", pkg.Publisher)
	}

	// At least one transition signature must bind a candidate key; extra
	// co-signers are allowed but cannot substitute for it.
	transitionKeys := make(map[string]bool, len(candidates))
	for _, cert := range transitionCerts {
		key := keyIDOf(cert.RawSubjectPublicKeyInfo)
		if publisherKeys[key] {
			if _, err := verifyPublisher(pkg, cert, c.Roots, now); err != nil {
				return res, err
			}
			transitionKeys[key] = true
		}
	}
	if len(transitionKeys) == 0 {
		return res, fail(CodeTransitionSignatureMissing, "transition is not signed by the package publisher")
	}

	// Try every candidate that signed the transition through the full
	// confirmation path; this preserves all authority checks while avoiding a
	// false rejection from a co-signer that lacks the operation grant.
	var lastRes ConfirmationResult
	var lastConfirmErr error
	for _, publisher := range candidates {
		if !transitionKeys[keyIDOf(publisher.RawSubjectPublicKeyInfo)] {
			continue
		}
		sig := transitionSignatureFor(publisher, c.TransitionSignatures, c.TransitionBytes)
		if sig == nil {
			continue
		}
		r, err := confirm(Confirmation{
			Package:             pkg,
			Transition:          tr,
			Definition:          c.Definition,
			Declaration:         c.Declaration,
			TransitionBytes:     c.TransitionBytes,
			TransitionSignature: sig,
			PublisherCert:       publisher,
			Roots:               c.Roots,
			rootSigners:         signers,
			State:               c.State,
			Policy:              c.Policy,
		})
		if err == nil {
			r.signed = true
			return r, nil
		}
		lastRes = r
		lastConfirmErr = err
	}
	if lastConfirmErr != nil {
		return lastRes, lastConfirmErr
	}
	return res, fail(CodePublisherMismatch, "no publisher candidate signed the transition")
}

// verifyChain checks a signer certificate against the configured trust roots at
// the deployer's replayable clock input.
func verifyChain(cert *x509.Certificate, roots []*x509.Certificate, now time.Time) error {
	if cert == nil {
		return fail(CodeSignatureMissing, "signer certificate is required")
	}
	if len(roots) == 0 {
		return fail(CodeSignatureChain, "no trust roots configured")
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		if r != nil {
			pool.AddCert(r)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: now,
	}); err != nil {
		return fail(CodeSignatureChain, "%s", err)
	}
	return nil
}

// transitionSignatureFor returns the transition signature made by pub's key.
func transitionSignatureFor(pub *x509.Certificate, signatures [][]byte, raw []byte) []byte {
	want := keyIDOf(pub.RawSubjectPublicKeyInfo)
	for _, sig := range signatures {
		cert, err := pkcs7.VerifyDetached(sig, raw)
		if err == nil && cert != nil && keyIDOf(cert.RawSubjectPublicKeyInfo) == want {
			return sig
		}
	}
	return nil
}
