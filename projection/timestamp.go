// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/semantics"
)

// TimestampAssertion is a pinned timestamp authority's statement that a report
// payload existed at Time.  The token is a PKCS#7 detached signature over the
// JCS form of {digest, time}; it is not an RFC 3161 TimeStampToken, but it is
// verified with the same trust inputs (a pinned TSA chain and the timestamping
// extended key usage).
type TimestampAssertion struct {
	// Digest is the digest of PAE(payloadType, payload).
	Digest Digest `json:"digest"`
	// Time is the TSA-asserted instant.
	Time time.Time `json:"time"`
	// Token is the base64url PKCS#7 signature over the assertion body.
	Token string `json:"token"`
}

// timestampBody is the exact signed object.
type timestampBody struct {
	Digest Digest `json:"digest"`
	Time   string `json:"time"`
}

// EnvelopeDigest returns the digest a timestamp assertion covers.
func EnvelopeDigest(env *Envelope) (Digest, error) {
	payload, _, err := EnvelopeBytes(env)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(semantics.PAE(env.PayloadType, payload))
	return DigestFromBytes(sum[:]), nil
}

func timestampBytes(digest Digest, at time.Time) ([]byte, error) {
	return semantics.CanonicalJSON(timestampBody{
		Digest: digest,
		Time:   at.UTC().Format(time.RFC3339),
	})
}

// NewTimestampAssertion signs the timestamp body for an envelope.
func NewTimestampAssertion(env *Envelope, at time.Time, cert *x509.Certificate, signer crypto.Signer) (*TimestampAssertion, error) {
	digest, err := EnvelopeDigest(env)
	if err != nil {
		return nil, err
	}
	body, err := timestampBytes(digest, at)
	if err != nil {
		return nil, err
	}
	der, err := pkcs7.BuildSignedData(pkcs7.OIDData, body, cert, signer, nil)
	if err != nil {
		return nil, reportFail(CodeReportSignature, "sign timestamp: %s", err)
	}
	return &TimestampAssertion{
		Digest: digest,
		Time:   at.UTC(),
		Token:  base64.RawURLEncoding.EncodeToString(der),
	}, nil
}

// verifyTimestamp checks the TSA chain, the signature, the payload binding and
// the asserted instant.
func verifyTimestamp(assertion *TimestampAssertion, env *Envelope, roots []*x509.Certificate, now time.Time, skew time.Duration) error {
	if assertion == nil {
		return reportFail(CodeReportStale, "timestamp assertion is required")
	}
	want, err := EnvelopeDigest(env)
	if err != nil {
		return reportFail(CodeReportShape, "%s", err)
	}
	if assertion.Digest != want {
		return reportFail(CodeReportStale, "timestamp digest does not match the report payload")
	}
	if len(roots) == 0 {
		return reportFail(CodeReportStale, "no timestamp trust roots configured")
	}
	body, err := timestampBytes(assertion.Digest, assertion.Time)
	if err != nil {
		return reportFail(CodeReportStale, "timestamp body: %s", err)
	}
	if len(assertion.Token) > base64.RawURLEncoding.EncodedLen(MaxSignatureBytes) {
		return reportFail(CodeReportStale, "timestamp token is too large")
	}
	token, err := base64.RawURLEncoding.DecodeString(assertion.Token)
	if err != nil {
		return reportFail(CodeReportStale, "timestamp token is not base64url: %s", err)
	}
	if base64.RawURLEncoding.EncodeToString(token) != assertion.Token {
		return reportFail(CodeReportStale, "timestamp token is not canonical base64url")
	}
	cert, err := pkcs7.VerifyDetached(token, body)
	if err != nil {
		return reportFail(CodeReportStale, "timestamp signature: %s", err)
	}
	if cert == nil {
		return reportFail(CodeReportStale, "timestamp signature recovered no certificate")
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		if root != nil {
			pool.AddCert(root)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime: now,
	}); err != nil {
		return reportFail(CodeReportStale, "timestamp signer chain: %s", err)
	}
	if assertion.Time.Before(cert.NotBefore) || assertion.Time.After(cert.NotAfter) {
		return reportFail(CodeReportStale,
			"timestamp %s is outside the signer certificate validity",
			assertion.Time.UTC().Format(time.RFC3339))
	}
	if assertion.Time.After(now.Add(skew)) {
		return reportFail(CodeReportStale, "timestamp %s is in the future", assertion.Time.UTC().Format(time.RFC3339))
	}
	return nil
}
