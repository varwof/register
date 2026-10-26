// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

// E1: the profile digest is content-derived, so pinning it pins the content.
func TestProfileDigestIsContentDerived(t *testing.T) {
	profile := &projection.Profile{ID: "test/profile", StatusModel: projection.StatusNone}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("sealed profile rejected: %v", err)
	}
	original := profile.ProfileDigest
	profile.ID = "test/other"
	if err := profile.Validate(); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportProfile) {
		t.Fatalf("content change kept the digest valid: %v", err)
	}
	profile.ID = "test/profile"
	if profile.ProfileDigest != original {
		t.Fatal("digest is not deterministic")
	}
}

// E1: a stale or swapped digest is refused.
func TestProfileDigestMismatchRejected(t *testing.T) {
	profile := &projection.Profile{ID: "test/profile", StatusModel: projection.StatusNone}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	profile.ProfileDigest = testDigest('0')
	if err := profile.Validate(); err == nil {
		t.Fatal("mismatched profile digest was accepted")
	}
}

// E2: the signed completeness boolean is recomputed, not trusted.
func TestVerifyRejectsTamperedCompleteness(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.NativeChecksComplete = false
	err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{})
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportIncomplete) {
		t.Fatalf("tampered completeness error = %v", err)
	}
}

// E1: the requirement is pinned by digest; swapping it is refused.
func TestVerifyPinsRequirementDigest(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	want, err := report.Requirement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report.ProjectedRequirementDigest = &want
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequirementDigest: &want,
	}); err != nil {
		t.Fatalf("pinned requirement rejected: %v", err)
	}

	other, err := semantics.DigestOf(map[string]any{"not": "the requirement"})
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequirementDigest: &other,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("wrong requirement pin error = %v", err)
	}

	// A digest that does not belong to the embedded requirement is a shape
	// error even before the policy pin.
	report.ProjectedRequirementDigest = &other
	if err := projection.ValidateEvidenceReport(report); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportDigest) {
		t.Fatalf("self-inconsistent requirement digest error = %v", err)
	}
}

// E1: a verifier profile revision can be allowlisted.
func TestVerifyPinsVerifierProfileDigest(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	bindVerifier(report, "principal:report-verifier")
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		VerifierProfileDigests: []projection.Digest{testDigest('b')},
	}); err != nil {
		t.Fatalf("allowlisted verifier profile rejected: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		VerifierProfileDigests: []projection.Digest{testDigest('c')},
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("disallowed verifier profile error = %v", err)
	}
}

// E1: a profile in a signed report must carry its content-derived digest.
func TestSignedReportRejectsUnsealedProfile(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.Profile.ProfileDigest = ""
	bindVerifier(report, "principal:report-verifier")
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	env, err := projection.SignEvidenceReport(report, cert, key)
	if err != nil {
		t.Fatalf("sign unsealed profile: %v", err)
	}
	if _, _, err := projection.VerifySignedEvidenceReport(env, projection.ReportPolicy{
		Roots: []*x509.Certificate{cert},
		Now:   now,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportProfile) {
		t.Fatalf("unsealed profile error = %v", err)
	}
}

// D3: identical facts are allowed only when each record binds a distinct index.
func TestDuplicateFactsRequireDistinctIndexes(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.Facts = append(report.Facts, report.Facts[0])

	first, second := 0, 1
	extra := report.EvidenceRecords[0]
	extra.FactIndex = &second
	report.EvidenceRecords[0].FactIndex = &first
	report.EvidenceRecords = append(report.EvidenceRecords, extra)
	if err := projection.ValidateEvidenceReport(report); err != nil {
		t.Fatalf("distinct fact indexes rejected: %v", err)
	}

	report.EvidenceRecords[1].FactIndex = &first
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportFactUnbound) {
		t.Fatalf("duplicate fact index error = %v", err)
	}
}

// E3: a record must name the report's observation.
func TestValidateRejectsObservationMismatch(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.EvidenceRecords[0].ObservationID = "another-action"
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportCheckBinding) {
		t.Fatalf("observation mismatch error = %v", err)
	}

	report, _ = consistentProfileReport(t, now)
	report.Observation = nil
	err = projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportCheckBinding) {
		t.Fatalf("observation-less record error = %v", err)
	}
}

// E4: a snapshot source outside the allowlist cannot reset rollback state.
func TestSnapshotSourceAllowlist(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report := reportWithSnapshot(t, now, 5, testDigest('1'))
	if _, err := projection.CheckReportLifecycle(report, projection.ReportPolicy{
		SnapshotSources: []string{"aeb-status"},
	}); err != nil {
		t.Fatalf("allowed snapshot source rejected: %v", err)
	}
	if _, err := projection.CheckReportLifecycle(report, projection.ReportPolicy{
		SnapshotSources: []string{"other-source"},
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportSnapshotSource) {
		t.Fatalf("disallowed snapshot source error = %v", err)
	}
}

// Item 2: reasons must live in the profile's namespace, and a pinned registry
// decides which codes are allowed.
func TestReasonNamespaceAndRegistry(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	artifact := testDigest('a')
	registryDigest := testDigest('7')
	expectation := projection.NativeCheckExpectation{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: artifact}
	profile := &projection.Profile{
		ID:                   "test/reasons",
		StatusModel:          projection.StatusRequired,
		RequiredChecks:       []string{"native:approval"},
		Expectations:         []projection.NativeCheckExpectation{expectation},
		ReasonNamespace:      "test",
		ReasonRegistryDigest: registryDigest,
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	build := func(reason string) (*projection.Report, error) {
		result := nativeResult("native:approval", "approval", projection.NativeCheckSuccess, now)
		result.EvidenceDigest = artifact
		result.Reason = reason
		return projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:        "test/projector",
			NativeCheckResults: []projection.NativeCheckResult{result},
			Profile:            profile,
			Now:                now,
		})
	}

	if _, err := build("other:code"); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportProfile) {
		t.Fatalf("foreign reason namespace error = %v", err)
	}
	report, err := build("test:fine")
	if err != nil {
		t.Fatalf("namespaced reason rejected: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{}); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("missing reason registry error = %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		ReasonRegistries: map[projection.Digest]map[string]bool{registryDigest: {"fine": true}},
	}); err != nil {
		t.Fatalf("registered reason rejected: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		ReasonRegistries: map[projection.Digest]map[string]bool{registryDigest: {"other": true}},
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("unregistered reason error = %v", err)
	}
}

func TestReasonNamespaceShape(t *testing.T) {
	for _, bad := range []string{"Bad", "-bad", "bad space", ""} {
		profile := &projection.Profile{ID: "test", StatusModel: projection.StatusNone, ReasonNamespace: bad}
		if bad == "" {
			if err := profile.Validate(); err != nil {
				t.Fatalf("empty namespace should be allowed: %v", err)
			}
			continue
		}
		if err := profile.Validate(); err == nil {
			t.Fatalf("namespace %q was accepted", bad)
		}
	}
}

// Item 1: DSSE payload and signatures must be canonical unpadded base64url.
func TestEnvelopeRejectsNonCanonicalBase64(t *testing.T) {
	for name, payload := range map[string]string{
		"padded":        "e30=",
		"standard b64":  "e30/",
		"invalid chars": "!!!!",
	} {
		t.Run(name, func(t *testing.T) {
			env := &projection.Envelope{
				PayloadType: projection.ReportPayloadType,
				Payload:     payload,
				Signatures:  []projection.Signature{{Sig: "AA"}},
			}
			if _, _, err := projection.EnvelopeBytes(env); err == nil {
				t.Fatalf("payload %q accepted", payload)
			}
		})
	}
}

// derivedReport builds a report with a generated derivation record.
func derivedReport(t *testing.T, now time.Time) (*projection.Report, projection.Digest) {
	t.Helper()
	artifact := projection.DigestFromBytes(func() []byte {
		sum := sha256.Sum256([]byte("artifact-bytes"))
		return sum[:]
	}())
	fact := semantics.EvidenceFact{
		Type: "human-authorization", Subject: "user:alice", Verified: true,
		IssuedAt: now.Add(-time.Minute),
	}
	result := nativeResult("native:approval", "approval", projection.NativeCheckSuccess, now)
	result.EvidenceDigest = artifact
	profile := &projection.Profile{
		ID:             "test/derivation",
		StatusModel:    projection.StatusRequired,
		RequiredChecks: []string{"native:approval"},
		Expectations:   []projection.NativeCheckExpectation{{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: artifact}},
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:        "test/projector",
		CarrierID:          "test/carrier",
		Verifier:           &projection.VerifierIdentity{Principal: result.Verifier, VerifierProfileDigest: result.VerifierProfileDigest},
		Facts:              []semantics.EvidenceFact{fact},
		NativeCheckResults: []projection.NativeCheckResult{result},
		Observation:        &projection.ProjectedObservation{NativeActionDigest: "obs"},
		EvidenceRecords: []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: artifact,
			ObservationID:  "obs",
			Fact:           &fact,
			NativeCheckIDs: []string{"native:approval"},
		}},
		Profile: profile,
		Now:     now,
	})
	if err != nil {
		t.Fatalf("derived report rejected: %v", err)
	}
	return report, artifact
}

func TestDerivationRecordsGenerated(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, artifact := derivedReport(t, now)
	if len(report.Derivations) != 1 {
		t.Fatalf("derivations = %+v", report.Derivations)
	}
	deriv := report.Derivations[0]
	if deriv.CarrierID != "test/carrier" || deriv.ArtifactDigest != artifact || deriv.FactIndex != 0 {
		t.Fatalf("derivation = %+v", deriv)
	}
	if err := projection.ValidateEvidenceReport(report); err != nil {
		t.Fatalf("derived report invalid: %v", err)
	}
}

func TestDerivationTamperRejected(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := derivedReport(t, now)
	report.Derivations[0].FactDigest = testDigest('0')
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportDerivation) {
		t.Fatalf("tampered derivation error = %v", err)
	}
}

func TestDerivationPolicyChecks(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, artifact := derivedReport(t, now)
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequireDerivations: true,
		Artifacts:          map[projection.Digest][]byte{artifact: []byte("artifact-bytes")},
		RequireArtifacts:   true,
	}); err != nil {
		t.Fatalf("valid derivation/artifact rejected: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequireDerivations: true,
		Artifacts:          map[projection.Digest][]byte{artifact: []byte("other-bytes")},
		RequireArtifacts:   true,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("artifact hash mismatch error = %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequireDerivations: true,
		RequireArtifacts:   true,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("missing artifact error = %v", err)
	}
	report.Derivations = nil
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequireDerivations: true,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("missing derivation error = %v", err)
	}
}

func TestSignedReportAttestation(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	digest, err := projection.EnvelopeDigest(env)
	if err != nil {
		t.Fatal(err)
	}
	signed := &projection.SignedReport{
		Envelope: env,
		Attestation: &projection.Attestation{
			Type:   "test-quote",
			Digest: digest,
			Quote:  "cXVvdGU",
		},
	}
	checked := false
	policy := policyWithPins(report, projection.ReportPolicy{
		Roots: []*x509.Certificate{cert},
		Now:   now,
		AttestationVerifier: func(att projection.Attestation, got projection.Digest) error {
			checked = true
			if att.Type != "test-quote" || got != digest {
				return errors.New("bad attestation")
			}
			return nil
		},
	})
	if _, _, err := projection.VerifySignedReport(signed, policy); err != nil {
		t.Fatalf("attested report rejected: %v", err)
	}
	if !checked {
		t.Fatal("attestation verifier was not called")
	}

	signed.Attestation.Digest = testDigest('0')
	if _, _, err := projection.VerifySignedReport(signed, policy); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("wrong attestation digest error = %v", err)
	}

	signed.Attestation = nil
	if _, _, err := projection.VerifySignedReport(signed, policyWithPins(report, projection.ReportPolicy{
		Roots:              []*x509.Certificate{cert},
		Now:                now,
		RequireAttestation: true,
	})); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("missing attestation error = %v", err)
	}
}

// Size and count bounds: an untrusted envelope must not turn verification into
// an unbounded allocation or CPU loop.
func TestEnvelopeBounds(t *testing.T) {
	oversized := strings.Repeat("a", projection.MaxReportBytes+1)
	env := &projection.Envelope{
		PayloadType: projection.ReportPayloadType,
		Payload:     base64.RawURLEncoding.EncodeToString([]byte(oversized)),
		Signatures:  []projection.Signature{{Sig: "AA"}},
	}
	if _, _, err := projection.EnvelopeBytes(env); err == nil {
		t.Fatal("oversized payload accepted")
	}

	many := make([]projection.Signature, projection.MaxEnvelopeSignatures+1)
	for i := range many {
		many[i] = projection.Signature{Sig: "AA"}
	}
	if _, _, err := projection.EnvelopeBytes(&projection.Envelope{
		PayloadType: projection.ReportPayloadType,
		Payload:     "e30",
		Signatures:  many,
	}); err == nil {
		t.Fatal("oversized signature list accepted")
	}

	big := base64.RawURLEncoding.EncodeToString(make([]byte, projection.MaxSignatureBytes+1))
	if _, _, err := projection.EnvelopeBytes(&projection.Envelope{
		PayloadType: projection.ReportPayloadType,
		Payload:     "e30",
		Signatures:  []projection.Signature{{Sig: big}},
	}); err == nil {
		t.Fatal("oversized signature accepted")
	}
}

// A derivation cannot name a verifier profile different from the report's.
func TestDerivationVerifierProfileConsistency(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := derivedReport(t, now)
	report.Derivations[0].VerifierProfileDigest = testDigest('0')
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportDerivation) {
		t.Fatalf("derivation verifier mismatch error = %v", err)
	}
}

// Lifecycle policy is applied on the unsigned path too.
func TestUnsignedVerifyAppliesLifecyclePolicy(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report := reportWithSnapshot(t, now, 5, testDigest('1'))
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		SnapshotSources: []string{"other-source"},
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportSnapshotSource) {
		t.Fatalf("unsigned lifecycle policy error = %v", err)
	}
}

// A timestamp signed outside the TSA certificate's validity is refused even if
// the chain is valid at verification time.
func TestTimestampSignerValidityAtAssertion(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, cert, _, report := signedReport(t, now, "principal:report-verifier")
	tsaCert, tsaKey := testTimestampCert(t, now) // valid from now-1h
	assertion, err := projection.NewTimestampAssertion(env, now.Add(-2*time.Hour), tsaCert, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = projection.VerifySignedEvidenceReportAt(env, assertion, policyWithPins(report, projection.ReportPolicy{
		Roots:          []*x509.Certificate{cert},
		TimestampRoots: []*x509.Certificate{tsaCert},
		Now:            now,
	}))
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportStale) {
		t.Fatalf("timestamp before signer validity error = %v", err)
	}
}

func TestAttestationQuoteMustBeCanonical(t *testing.T) {
	for _, quote := range []string{"cXVvdGU=", "!!!!", "cXVv dGU"} {
		if _, err := projection.DecodeAttestationQuote(projection.Attestation{Quote: quote}); err == nil {
			t.Fatalf("quote %q accepted", quote)
		}
	}
}

// Assurance is part of the signed payload and is checked against the evidence
// actually present.
func TestReportAssuranceRules(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)

	basic, _ := consistentProfileReport(t, now)
	if basic.Assurance != projection.AssuranceE1 {
		t.Fatalf("default assurance = %q, want E1", basic.Assurance)
	}
	derived, _ := derivedReport(t, now)
	if derived.Assurance != projection.AssuranceE2 {
		t.Fatalf("derived assurance = %q, want E2", derived.Assurance)
	}

	// Claiming E2 without derivations is refused at verification.
	tampered, _ := consistentProfileReport(t, now)
	tampered.Assurance = projection.AssuranceE2
	if err := projection.VerifyEvidenceReport(tampered, projection.ReportPolicy{}); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("E2 without derivations error = %v", err)
	}

	// E3 needs attestation verification, which the unsigned path cannot do.
	e3, _ := consistentProfileReport(t, now)
	e3.Assurance = projection.AssuranceE3
	if err := projection.VerifyEvidenceReport(e3, projection.ReportPolicy{}); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("E3 without attestation error = %v", err)
	}

	// A minimum assurance is enforced.
	if err := projection.VerifyEvidenceReport(basic, projection.ReportPolicy{
		MinAssurance: projection.AssuranceE2,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("minimum assurance error = %v", err)
	}

	// An unknown minimum is a configuration error, not a silent E1 floor.
	if err := projection.VerifyEvidenceReport(basic, projection.ReportPolicy{
		MinAssurance: projection.AssuranceLevel("E9"),
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportPolicy) {
		t.Fatalf("unknown minimum assurance error = %v", err)
	}
}

func TestReportVersionRequired(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.Version = "CLC-EVIDENCE-REPORT-v0"
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportShape) {
		t.Fatalf("unknown version error = %v", err)
	}
	report.Version = ""
	if err := projection.ValidateEvidenceReport(report); err == nil {
		t.Fatal("empty version accepted")
	}
}

// A deployer can pin required checks independently of the report's own list.
func TestPolicyPinsRequiredCheckIDs(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{}); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequiredCheckIDs: []string{"native:approval", "native:missing"},
	})
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportIncomplete) {
		t.Fatalf("pinned missing check error = %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{
		RequiredCheckIDs: []string{"native:approval"},
	}); err != nil {
		t.Fatalf("pinned existing check rejected: %v", err)
	}
}
