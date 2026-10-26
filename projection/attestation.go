// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/varwof/register/internal/jsonstrict"
)

// Attestation is an opaque execution attestation carried beside the signed
// envelope.  The report layer does not implement any TEE; the deployer supplies
// an AttestationVerifier that knows how to check the quote and bind it to the
// payload digest.
type Attestation struct {
	// Type names the attestation format, e.g. "sev-snp" or "tdx".
	Type string `json:"type"`
	// Digest is the digest of the signed envelope (EnvelopeDigest).
	Digest Digest `json:"digest"`
	// Quote is base64url opaque attestation bytes.
	Quote string `json:"quote"`
}

// SignedReport is the transport object: a DSSE envelope plus optional
// out-of-band evidence about when and where it was produced.
type SignedReport struct {
	Envelope    *Envelope           `json:"envelope"`
	Timestamp   *TimestampAssertion `json:"timestamp,omitempty"`
	Attestation *Attestation        `json:"attestation,omitempty"`
}

// VerifySignedReport verifies a SignedReport: the attestation (when present or
// required), the timestamp (when present or required) and the envelope's
// signatures and policy.
func VerifySignedReport(signed *SignedReport, policy ReportPolicy) (*Report, SnapshotState, error) {
	if signed == nil || signed.Envelope == nil {
		return nil, nil, reportFail(CodeReportShape, "signed report has no envelope")
	}
	digest, err := EnvelopeDigest(signed.Envelope)
	if err != nil {
		return nil, nil, reportFail(CodeReportShape, "%s", err)
	}
	switch {
	case signed.Attestation != nil:
		if signed.Attestation.Digest != digest {
			return nil, nil, reportFail(CodeReportPolicy,
				"attestation digest does not match the signed payload")
		}
		if policy.AttestationVerifier == nil {
			return nil, nil, reportFail(CodeReportPolicy,
				"no attestation verifier configured")
		}
		if err := policy.AttestationVerifier(*signed.Attestation, digest); err != nil {
			return nil, nil, reportFail(CodeReportPolicy, "attestation: %s", err)
		}
		policy.attestationVerified = true
	case policy.RequireAttestation:
		return nil, nil, reportFail(CodeReportPolicy, "report has no attestation")
	}
	return VerifySignedEvidenceReportAt(signed.Envelope, signed.Timestamp, policy)
}

// DecodeAttestationQuote decodes the base64url quote bytes.
func DecodeAttestationQuote(attestation Attestation) ([]byte, error) {
	if len(attestation.Quote) > base64.RawURLEncoding.EncodedLen(1<<20) {
		return nil, fmt.Errorf("attestation quote is too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(attestation.Quote)
	if err != nil {
		return nil, fmt.Errorf("attestation quote is not base64url: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != attestation.Quote {
		return nil, fmt.Errorf("attestation quote is not canonical base64url")
	}
	return raw, nil
}

// DecodeSignedReport parses a signed report from JSON.  Unknown members, a
// duplicate member and trailing data are refused; the artifact is bounded
// before decoding.
func DecodeSignedReport(raw []byte) (*SignedReport, error) {
	if len(raw) > 3*MaxReportBytes {
		return nil, fmt.Errorf("signed report is %d bytes, limit is %d", len(raw), 3*MaxReportBytes)
	}
	if err := jsonstrict.Check(raw); err != nil {
		return nil, fmt.Errorf("signed report: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var signed SignedReport
	if err := dec.Decode(&signed); err != nil {
		return nil, fmt.Errorf("signed report: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("signed report has trailing data")
	}
	if signed.Envelope == nil {
		return nil, fmt.Errorf("signed report has no envelope")
	}
	return &signed, nil
}
