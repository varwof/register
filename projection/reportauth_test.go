// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/varwof/pkcs7"
	pki "github.com/varwof/types"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

// testVerifierCert builds a self-signed verifier certificate carrying an AIC
// whose principal key hash is the certificate's own key.
func testVerifierCert(t *testing.T, realm, id string, now time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	aic := pki.AIC{
		Version: 1,
		AgentId: "agent:report-verifier",
		PrincipalUid: pki.PrincipalUid{
			Realm:      realm,
			Identifier: id,
			KeyHash:    sum[:],
		},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "report-verification", Description: "verify evidence reports"},
			RequestedLifetime:  3600,
			Timestamp:          now,
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.SigAlgoToOID(x509.ECDSAWithSHA256),
			SignatureValue:     []byte{0x01},
		},
	}
	der, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(now.UnixNano()),
		Subject:         pkix.Name{CommonName: "report verifier"},
		NotBefore:       now.Add(-time.Hour),
		NotAfter:        now.Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: pki.OIDAIC, Value: der}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// bindVerifier makes the report and every result name one verifier.
func bindVerifier(report *projection.Report, principal string) {
	report.Verifier = &projection.VerifierIdentity{
		Principal:             principal,
		VerifierProfileDigest: testDigest('b'),
	}
	for i := range report.NativeCheckResults {
		report.NativeCheckResults[i].Verifier = principal
		report.NativeCheckResults[i].VerifierProfileDigest = testDigest('b')
	}
}

// policyWithPins fills the mandatory pins from the report under test.
func policyWithPins(report *projection.Report, policy projection.ReportPolicy) projection.ReportPolicy {
	if report != nil {
		if report.Profile != nil {
			policy.ProfileDigest = report.Profile.ProfileDigest
		}
		if report.ProjectedRequirementDigest != nil {
			policy.RequirementDigest = report.ProjectedRequirementDigest
		}
	}
	return policy
}

func signedReport(t *testing.T, now time.Time, principal string) (*projection.Envelope, *x509.Certificate, crypto.Signer, *projection.Report) {
	t.Helper()
	report, _ := consistentProfileReport(t, now)
	report.Verifier = &projection.VerifierIdentity{
		Principal:             principal,
		VerifierProfileDigest: testDigest('b'),
	}
	bindVerifier(report, principal)
	cert, key := testVerifierCert(t, "corp.example", strings.TrimPrefix(principal, "principal:"), now)
	env, err := projection.SignEvidenceReport(report, cert, key)
	if err != nil {
		t.Fatalf("sign report: %v", err)
	}
	return env, cert, key, report
}

func TestSignedReportRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	verified, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots:              []*x509.Certificate{cert},
		Now:                now.Add(time.Minute),
		MaxAge:             24 * time.Hour,
		VerifierPrincipals: []string{"principal:report-verifier"},
	}))
	if err != nil {
		t.Fatalf("verified report rejected: %v", err)
	}
	if verified.NativeChecksComplete != true {
		t.Fatal("verified report lost its completeness")
	}
	if verified.Satisfaction == nil || verified.Satisfaction.Satisfaction().Verdict != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %+v", verified.Satisfaction)
	}
}

func TestSignedReportRejectsTamperedPayload(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	rawPayload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rawPayload[0] ^= 0x01
	env.Payload = base64.RawURLEncoding.EncodeToString(rawPayload)
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots: []*x509.Certificate{cert}, Now: now,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportSignature) {
		t.Fatalf("tampered payload error = %v", err)
	}
}

func TestSignedReportRejectsUntrustedRoot(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, _, _, report := signedReport(t, now, "principal:report-verifier")
	other, _ := testVerifierCert(t, "other.example", "other", now)
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots: []*x509.Certificate{other}, Now: now,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportSignature) {
		t.Fatalf("untrusted root error = %v", err)
	}
}

func TestSignedReportRejectsStale(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots:  []*x509.Certificate{cert},
		Now:    now.Add(2 * time.Hour),
		MaxAge: time.Hour,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("stale report error = %v", err)
	}
}

func TestSignedReportRejectsVerifierNotInPolicy(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots:              []*x509.Certificate{cert},
		Now:                now,
		VerifierPrincipals: []string{"principal:someone-else"},
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("disallowed verifier error = %v", err)
	}
}

// A signer cannot sign a report that claims a different verifier, and a
// hand-built envelope whose signer does not match is refused on verification.
func TestSignedReportRejectsVerifierMismatch(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	bindVerifier(report, "principal:somebody-else")
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	if _, err := projection.SignEvidenceReport(report, cert, key); err == nil {
		t.Fatal("signed a report claiming another verifier")
	}
}

// Even a genuine verifier signature does not make a forged verdict true: the
// satisfaction is recomputed at the appraisal instant.
func TestSignedReportRejectsForgedVerdict(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	bindVerifier(report, "principal:report-verifier")
	report.Satisfaction.Verdict = semantics.EvidenceViolated
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	env, err := projection.SignEvidenceReport(report, cert, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots: []*x509.Certificate{cert}, Now: now,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportVerdict) {
		t.Fatalf("forged verdict error = %v", err)
	}
}

// The signed bytes must be the canonical report form; a valid signature over a
// non-canonical encoding is refused because two encodings would otherwise be
// interchangeable under one signature.
func TestSignedReportRejectsNonCanonicalPayload(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.Verifier = &projection.VerifierIdentity{
		Principal:             "principal:report-verifier",
		VerifierProfileDigest: testDigest('b'),
	}
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	indented, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs7.BuildSignedData(pkcs7.OIDData, semantics.PAE(projection.ReportPayloadType, indented), cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &projection.Envelope{
		PayloadType: projection.ReportPayloadType,
		Payload:     base64.RawURLEncoding.EncodeToString(indented),
		Signatures:  []projection.Signature{{Sig: base64.RawURLEncoding.EncodeToString(der)}},
	}
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots: []*x509.Certificate{cert}, Now: now,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportShape) {
		t.Fatalf("non-canonical payload error = %v", err)
	}
}

func TestSignedReportRequiresProfileWhenPolicySaysSo(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.Profile = nil
	report.NativeCheckAssessment = nil
	bindVerifier(report, "principal:report-verifier")
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	env, err := projection.SignEvidenceReport(report, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		Now:            now,
		RequireProfile: true,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportProfile) {
		t.Fatalf("profile-less report error = %v", err)
	}
}
