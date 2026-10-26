// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	pki "github.com/varwof/types"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/semantics"
)

// ReportPayloadType is the DSSE payload type a signed evidence report uses.
const ReportPayloadType = "application/vnd.varwof.clc-evidence-report-v1+json"

// reportClockSkew is the tolerated forward error for the appraisal instant.
const reportClockSkew = 5 * time.Minute

// SignEvidenceReport signs the JCS encoding of rep inside a DSSE envelope.  The
// signature covers PAE(ReportPayloadType, payload), so the payload cannot be
// replayed under a different type.  The signing certificate must carry an AIC
// that names the report's declared verifier and its key.
func SignEvidenceReport(rep *Report, cert *x509.Certificate, signer crypto.Signer) (*Envelope, error) {
	if rep == nil || cert == nil || signer == nil {
		return nil, reportFail(CodeReportSignature, "report, certificate and signer are required")
	}
	// The requirement digest is part of the signed payload: fill it before
	// canonicalization so the verifier can pin the exact requirement.
	if rep.Requirement != nil && rep.ProjectedRequirementDigest == nil {
		digest, err := rep.Requirement.Digest()
		if err != nil {
			return nil, reportFail(CodeReportShape, "requirement digest: %s", err)
		}
		rep.ProjectedRequirementDigest = &digest
	}
	if rep.Verifier == nil {
		return nil, reportFail(CodeReportVerifier, "report has no verifier identity")
	}
	if err := ValidateEvidenceReport(rep); err != nil {
		return nil, err
	}
	aic, err := certificateIdentity(cert)
	if err != nil {
		return nil, err
	}
	if !principalMatches(rep.Verifier.Principal, aic) {
		return nil, reportFail(CodeReportVerifier,
			"signing certificate names %s:%s, report names %q",
			aic.PrincipalUid.Realm, aic.PrincipalUid.Identifier, rep.Verifier.Principal)
	}

	payload, err := semantics.CanonicalJSON(rep)
	if err != nil {
		return nil, reportFail(CodeReportShape, "canonical report: %s", err)
	}
	der, err := pkcs7.BuildSignedData(
		pkcs7.OIDData,
		semantics.PAE(ReportPayloadType, payload),
		cert,
		signer,
		nil,
	)
	if err != nil {
		return nil, reportFail(CodeReportSignature, "sign report: %s", err)
	}
	keyID := base64.RawURLEncoding.EncodeToString(mustKeyHash(cert))
	return &Envelope{
		PayloadType: ReportPayloadType,
		Payload:     base64.RawURLEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: keyID,
			Sig:   base64.RawURLEncoding.EncodeToString(der),
		}},
	}, nil
}

// VerifySignedEvidenceReport verifies every signature over the DSSE payload,
// binds the signer to the report's declared verifier through its AIC, enforces
// the deployer policy, and finally recomputes the CLC satisfaction at the
// report's own appraisal instant.
//
// The payload is parsed only after signature and chain verification, and the
// parsed report must re-canonicalize to exactly the signed bytes: a payload
// that is valid JSON but not the canonical report form is refused.
func VerifySignedEvidenceReport(env *Envelope, policy ReportPolicy) (*Report, SnapshotState, error) {
	return VerifySignedEvidenceReportAt(env, nil, policy)
}

// VerifySignedEvidenceReportAt is VerifySignedEvidenceReport with an optional
// timestamp assertion.  When one is present (or required by policy), MaxAge is
// measured from the timestamp authority's instant rather than the report's
// self-declared appraisal time.
func VerifySignedEvidenceReportAt(env *Envelope, assertion *TimestampAssertion, policy ReportPolicy) (*Report, SnapshotState, error) {
	if env == nil {
		return nil, nil, reportFail(CodeReportShape, "envelope is nil")
	}
	if env.PayloadType != ReportPayloadType {
		return nil, nil, reportFail(CodeReportShape, "payload type %q is not %q", env.PayloadType, ReportPayloadType)
	}
	payload, signatures, err := EnvelopeBytes(env)
	if err != nil {
		return nil, nil, reportFail(CodeReportShape, "%s", err)
	}
	if len(payload) == 0 {
		return nil, nil, reportFail(CodeReportShape, "envelope has no payload")
	}
	if len(signatures) == 0 {
		return nil, nil, reportFail(CodeReportSignature, "envelope has no signatures")
	}
	now := policy.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pae := semantics.PAE(ReportPayloadType, payload)

	var anchor time.Time
	anchorSkew := reportClockSkew
	if policy.TimestampClockSkew > 0 {
		anchorSkew = policy.TimestampClockSkew
	}
	if assertion != nil || policy.RequireTimestamp {
		if err := verifyTimestamp(assertion, env, policy.TimestampRoots, now, anchorSkew); err != nil {
			return nil, nil, err
		}
		anchor = assertion.Time
	}

	signers := make([]*pki.AIC, 0, len(signatures))
	for i, sig := range signatures {
		cert, err := pkcs7.VerifyDetached(sig, pae)
		if err != nil {
			return nil, nil, reportFail(CodeReportSignature, "signature %d: %s", i, err)
		}
		if cert == nil {
			return nil, nil, reportFail(CodeReportSignature, "signature %d recovered no certificate", i)
		}
		if err := verifyReportCertificate(cert, policy.Roots, now); err != nil {
			return nil, nil, reportFail(CodeReportSignature, "signature %d: %s", i, err)
		}
		aic, err := certificateIdentity(cert)
		if err != nil {
			return nil, nil, reportFail(CodeReportSignature, "signature %d: %s", i, err)
		}
		if len(policy.VerifierPrincipals) > 0 && !principalAllowed(policy.VerifierPrincipals, aic) {
			return nil, nil, reportFail(CodeReportPolicy, "signature %d signer is not an allowed verifier", i)
		}
		signers = append(signers, aic)
	}

	report, err := decodeSignedReport(payload)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := semantics.CanonicalJSON(report)
	if err != nil {
		return nil, nil, reportFail(CodeReportShape, "canonical report: %s", err)
	}
	if !bytes.Equal(canonical, payload) {
		return nil, nil, reportFail(CodeReportShape, "signed payload is not the canonical report form")
	}
	if report.Verifier == nil {
		return nil, nil, reportFail(CodeReportVerifier, "report has no verifier identity")
	}
	if report.Profile != nil {
		if report.Profile.ProfileDigest.Empty() {
			return nil, nil, reportFail(CodeReportProfile,
				"embedded profile is not sealed (missing content-derived digest)")
		}
		if policy.ProfileDigest.Empty() {
			return nil, nil, reportFail(CodeReportPolicy,
				"report embeds a profile but the policy pins no ProfileDigest")
		}
	}
	if report.Requirement != nil && policy.RequirementDigest == nil {
		return nil, nil, reportFail(CodeReportPolicy,
			"report carries a requirement but the policy pins no RequirementDigest")
	}
	for i, aic := range signers {
		if !principalMatches(report.Verifier.Principal, aic) {
			return nil, nil, reportFail(CodeReportVerifier,
				"signature %d signer %s:%s is not the report verifier %q",
				i, aic.PrincipalUid.Realm, aic.PrincipalUid.Identifier, report.Verifier.Principal)
		}
	}

	if err := VerifyEvidenceReport(report, policy); err != nil {
		return nil, nil, err
	}
	if !policy.ProfileDigest.Empty() {
		if report.Profile == nil || report.Profile.ProfileDigest != policy.ProfileDigest {
			return nil, nil, reportFail(CodeReportPolicy, "report profile digest is not the pinned profile")
		}
	}
	if !anchor.IsZero() {
		// The report must have been appraised around the timestamped instant.
		// Allowing an old appraisal to be timestamped now would let a verifier
		// backdate freshness and still look current.
		if report.AppraisalTime.After(anchor.Add(anchorSkew)) ||
			anchor.Sub(*report.AppraisalTime) > anchorSkew {
			return nil, nil, reportFail(CodeReportStale,
				"report appraisal time and timestamp are more than %s apart", anchorSkew)
		}
	}
	if err := checkReportAge(report, policy, now, anchor); err != nil {
		return nil, nil, err
	}
	if err := recomputeSatisfaction(report); err != nil {
		return nil, nil, err
	}
	next, err := CheckReportLifecycle(report, policy)
	if err != nil {
		return nil, nil, err
	}
	return report, next, nil
}

// decodeSignedReport parses the payload as a closed report object.
func decodeSignedReport(payload []byte) (*Report, error) {
	if len(payload) > MaxReportBytes {
		return nil, reportFail(CodeReportShape, "payload is %d bytes, limit is %d", len(payload), MaxReportBytes)
	}
	if err := jsonstrict.Check(payload); err != nil {
		return nil, reportFail(CodeReportShape, "payload: %s", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var report Report
	if err := dec.Decode(&report); err != nil {
		return nil, reportFail(CodeReportShape, "payload: %s", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, reportFail(CodeReportShape, "payload has trailing data")
	}
	return &report, nil
}

// checkReportAge applies the deployer's report-age bound.
func checkReportAge(report *Report, policy ReportPolicy, now time.Time, anchor time.Time) error {
	if report.AppraisalTime == nil {
		return reportFail(CodeReportShape, "report has no appraisal time")
	}
	skew := reportClockSkew
	if policy.MaxClockSkew > 0 {
		skew = policy.MaxClockSkew
	}
	if report.AppraisalTime.After(now.Add(skew)) {
		return reportFail(CodeReportStale,
			"report appraisal time %s is outside the clock-skew window",
			report.AppraisalTime.UTC().Format(time.RFC3339))
	}
	reference := *report.AppraisalTime
	if !anchor.IsZero() {
		reference = anchor
	}
	if policy.MaxAge > 0 && now.Sub(reference) > policy.MaxAge {
		return reportFail(CodeReportStale, "report is older than %s", policy.MaxAge)
	}
	return nil
}

// recomputeSatisfaction re-runs the CLC evaluation at the report's own
// appraisal instant and requires an exact match.  The verdict in a report is
// never trusted; it is recomputed.
func recomputeSatisfaction(report *Report) error {
	if report.Requirement == nil {
		if report.Satisfaction != nil {
			return reportFail(CodeReportVerdict, "report carries a verdict without a requirement")
		}
		return nil
	}
	if report.Satisfaction == nil {
		return reportFail(CodeReportVerdict, "report has a requirement but no verdict")
	}
	got, err := semantics.EvaluateRequirement(
		*report.Requirement,
		report.Facts,
		semantics.EvidenceContext{Now: *report.AppraisalTime},
	)
	if err != nil {
		return reportFail(CodeReportShape, "re-evaluate requirement: %s", err)
	}
	if !reflect.DeepEqual(got, *report.Satisfaction) {
		return reportFail(CodeReportVerdict, "recomputed verdict does not match the report")
	}
	return nil
}

// verifyReportCertificate checks the signer chain at the verification instant.
func verifyReportCertificate(cert *x509.Certificate, roots []*x509.Certificate, now time.Time) error {
	if len(roots) == 0 {
		return fmt.Errorf("no trust roots configured")
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root != nil {
			pool.AddCert(root)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: now,
	}); err != nil {
		return fmt.Errorf("certificate chain: %w", err)
	}
	return nil
}

// certificateIdentity parses and validates the certificate's AIC, and checks
// that the AIC's principal key hash is the certificate's own key.
func certificateIdentity(cert *x509.Certificate) (*pki.AIC, error) {
	aic, err := pki.ParseAIC(cert)
	if err != nil {
		return nil, reportFail(CodeReportVerifier, "parse AIC: %s", err)
	}
	if aic == nil {
		return nil, reportFail(CodeReportVerifier, "certificate carries no AIC")
	}
	if err := pki.ValidateAIC(aic); err != nil {
		return nil, reportFail(CodeReportVerifier, "invalid AIC: %s", err)
	}
	if len(aic.PrincipalUid.KeyHash) == 0 || allZeroBytes(aic.PrincipalUid.KeyHash) {
		return nil, reportFail(CodeReportVerifier, "AIC carries no principal key hash")
	}
	if !bytes.Equal(aic.PrincipalUid.KeyHash, mustKeyHash(cert)) {
		return nil, reportFail(CodeReportVerifier, "AIC key hash does not match the certificate key")
	}
	return aic, nil
}

// principalMatches accepts "principal:<id>" or "<realm>:<id>".
func principalMatches(declared string, aic *pki.AIC) bool {
	want := strings.TrimPrefix(declared, "principal:")
	id := aic.PrincipalUid.Identifier
	return want == id || want == aic.PrincipalUid.Realm+":"+id
}

// principalAllowed checks the deployer's verifier allowlist.
func principalAllowed(allowed []string, aic *pki.AIC) bool {
	for _, entry := range allowed {
		if principalMatches(entry, aic) {
			return true
		}
	}
	return false
}

func mustKeyHash(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
