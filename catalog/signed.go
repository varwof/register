// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"crypto/x509"

	"github.com/varwof/pkcs7"
)

// VerifySigned is the consumer entry point that cannot forget the detached
// signature.  Verify alone takes a recovered certificate; a caller that skipped
// the PKCS#7 step could hand in an arbitrary trusted certificate and conclude
// that an artifact was signed by a principal that never saw it.  This function
// closes that gap: it verifies the detached signature over the exact bytes
// first, then parses the artifact and runs Verify with the recovered signer.
//
// The lower-level split is kept for callers that verify the signature
// elsewhere (the CLI decodes the PEM envelope first, and scheme administration
// has the same shape); those callers pass the recovered certificate to Verify
// directly and remain responsible for binding it to the bytes.
//
// The signature covers raw rather than a re-serialization, so callers must pass
// the bytes they received, not catalog.CanonicalBytes output.
func VerifySigned(raw, signature []byte, roots []*x509.Certificate, policy TrustPolicy, state RegistryState) (Result, error) {
	if len(raw) > maxArtifactBytes {
		err := fail(CodeCatalogShape, "artifact is %d bytes, limit is %d", len(raw), maxArtifactBytes)
		return Result{Verdict: VerdictReject, Reason: CodeOf(err), Detail: detailOf(err)}, err
	}
	if len(signature) == 0 {
		err := fail(CodeSignatureMissing, "detached catalogue signature is required")
		return Result{Verdict: VerdictReject, Reason: CodeOf(err), Detail: detailOf(err)}, err
	}
	signer, err := pkcs7.VerifyDetached(signature, raw)
	if err != nil {
		return Result{Verdict: VerdictReject, Reason: CodeSignatureInvalid, Detail: err.Error()},
			fail(CodeSignatureInvalid, "%s", err)
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return Result{Verdict: VerdictReject, Reason: CodeOf(err), Detail: detailOf(err)}, err
	}
	res, err := verify(Verification{
		Catalog:    *c,
		SignerCert: signer,
		Roots:      roots,
		Policy:     policy,
		State:      state,
	})
	if err == nil {
		res.signatureVerified = true
	}
	return res, err
}
