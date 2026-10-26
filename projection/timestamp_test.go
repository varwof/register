// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
)

// testTimestampCert builds a self-signed certificate with the timestamping
// extended key usage, which the TSA verification path requires.
func testTimestampCert(t *testing.T, now time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "test timestamp authority"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestTimestampAssertionRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	tsaCert, tsaKey := testTimestampCert(t, now)
	assertion, err := projection.NewTimestampAssertion(env, now.Add(time.Minute), tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, assertion, policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		TimestampRoots: []*x509.Certificate{tsaCert},
		Now:            now.Add(10 * time.Minute),
		MaxAge:         time.Hour,
	})); err != nil {
		t.Fatalf("timestamped report rejected: %v", err)
	}
}

func TestTimestampAssertionRejectsMissing(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	tsaCert, _ := testTimestampCert(t, now)
	_, _, err := projection.VerifySignedEvidenceReportAt(env, nil, policyWithPins(report, projection.ReportPolicy{
		Roots:            []*x509.Certificate{cert},
		TimestampRoots:   []*x509.Certificate{tsaCert},
		Now:              now.Add(time.Minute),
		RequireTimestamp: true,
	}))
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("missing timestamp error = %v", err)
	}
}

func TestTimestampAssertionRejectsTampering(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	tsaCert, tsaKey := testTimestampCert(t, now)
	assertion, err := projection.NewTimestampAssertion(env, now.Add(time.Minute), tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	policy := policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		TimestampRoots: []*x509.Certificate{tsaCert},
		Now:            now.Add(10 * time.Minute),
		MaxAge:         time.Hour,
	})

	tampered := *assertion
	tampered.Time = assertion.Time.Add(time.Minute)
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, &tampered, policy); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("tampered timestamp error = %v", err)
	}

	wrongDigest := *assertion
	wrongDigest.Digest = testDigest('0')
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, &wrongDigest, policy); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("wrong timestamp digest error = %v", err)
	}

	untrusted := policy
	untrusted.TimestampRoots = []*x509.Certificate{cert}
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, assertion, untrusted); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("untrusted timestamp root error = %v", err)
	}
}

func TestTimestampAssertionBoundsReportAge(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	tsaCert, tsaKey := testTimestampCert(t, now)
	assertion, err := projection.NewTimestampAssertion(env, now, tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, assertion, policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		TimestampRoots: []*x509.Certificate{tsaCert},
		Now:            now.Add(2 * time.Hour),
		MaxAge:         time.Hour,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("stale timestamped report error = %v", err)
	}

	// A timestamp long after the appraisal instant cannot make an old report
	// look current.
	late, err := projection.NewTimestampAssertion(env, now.Add(time.Hour), tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, late, policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		TimestampRoots: []*x509.Certificate{tsaCert},
		Now:            now.Add(2 * time.Hour),
		MaxAge:         3 * time.Hour,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("late timestamp error = %v", err)
	}

	// A timestamp that predates the report's appraisal instant cannot make it
	// look younger than it is.
	earlier, err := projection.NewTimestampAssertion(env, now.Add(-10*time.Minute), tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := projection.VerifySignedEvidenceReportAt(env, earlier, policyWithPins(report, projection.ReportPolicy{
		Roots:              []*x509.Certificate{cert},
		TimestampRoots:     []*x509.Certificate{tsaCert},
		Now:                now.Add(time.Minute),
		MaxAge:             time.Hour,
		TimestampClockSkew: time.Minute,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("appraisal-after-timestamp error = %v", err)
	}
}
