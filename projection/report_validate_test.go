// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

const reportRequirement = `{
  "@version": "CLC-REQUIREMENT-v1",
  "requirement_id": "report@1",
  "expression": "human-authorization"
}`

func reportRequirementValue(t *testing.T) semantics.Requirement {
	t.Helper()
	req, err := semantics.ParseRequirement([]byte(reportRequirement))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// consistentProfileReport builds a report that satisfies every M1/M2 rule:
// typed digests, a complete inventory, a lineage record for the one Fact and
// the gating check result over the same artifact.
func consistentProfileReport(t *testing.T, now time.Time) (*projection.Report, *semantics.EvidenceFact) {
	t.Helper()
	artifact := testDigest('a')
	fact := semantics.EvidenceFact{
		Type: "human-authorization", Subject: "user:alice", Verified: true,
		IssuedAt: now.Add(-time.Minute),
	}
	result := nativeResult("native:approval", "approval", projection.NativeCheckSuccess, now)
	result.EvidenceDigest = artifact
	req := reportRequirementValue(t)
	profile := &projection.Profile{
		ID:                  "test/profile",
		StatusModel:         projection.StatusRequired,
		RequiredChecks:      []string{"native:approval"},
		Expectations:        []projection.NativeCheckExpectation{{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: artifact}},
		ActionMappingDigest: testDigest('8'),
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:        "test/projector",
		Requirement:        &req,
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
		t.Fatalf("consistent report rejected: %v", err)
	}
	return report, &fact
}

func TestDigestCanonicalForm(t *testing.T) {
	valid := "sha-256:" + strings.Repeat("0f", 32)
	if err := projection.Digest(valid).Validate(); err != nil {
		t.Fatalf("canonical digest rejected: %v", err)
	}
	for _, bad := range []string{
		"",
		"sha256:" + strings.Repeat("0f", 32),
		"sha-256:" + strings.Repeat("0F", 32),
		"sha-256:" + strings.Repeat("0f", 31),
		"sha-256:" + strings.Repeat("0f", 32) + "0",
		"sha-384:" + strings.Repeat("0f", 32),
	} {
		if err := projection.Digest(bad).Validate(); err == nil {
			t.Fatalf("non-canonical digest %q was accepted", bad)
		}
	}
}

func TestFreshnessDecisionClosedSet(t *testing.T) {
	for _, verdict := range []projection.FreshnessVerdict{
		projection.FreshnessFresh, projection.FreshnessCached, projection.FreshnessStale,
	} {
		if err := (projection.FreshnessDecision{Verdict: verdict}).Validate(); err != nil {
			t.Fatalf("verdict %q rejected: %v", verdict, err)
		}
	}
	for _, bad := range []projection.FreshnessVerdict{"", "valid", "FRESH", "expired"} {
		if err := (projection.FreshnessDecision{Verdict: bad}).Validate(); err == nil {
			t.Fatalf("unknown freshness verdict %q accepted", bad)
		}
	}
}

// A success carrying a stale snapshot is a contradiction: the check says the
// artifact passed while its own freshness input says the snapshot expired.
func TestProjectRejectsStaleSuccess(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	result := nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now)
	result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessStale}
	if _, err := projection.Project([]byte(statusBothRequirement), projection.Options{
		Now:                now,
		RoleMap:            identityRoles("a", "b"),
		Facts:              []semantics.EvidenceFact{},
		NativeCheckResults: []projection.NativeCheckResult{result},
	}); err == nil {
		t.Fatal("success with a stale freshness decision was accepted")
	}
}

func TestProfileValidation(t *testing.T) {
	expectation := projection.NativeCheckExpectation{
		CheckID: "c", ComponentType: "ct", EvidenceDigest: testDigest('a'),
	}
	valid := projection.Profile{
		ID: "p", StatusModel: projection.StatusRequired,
		RequiredChecks: []string{"c"}, Expectations: []projection.NativeCheckExpectation{expectation},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	for name, mutate := range map[string]func(*projection.Profile){
		"no id":                func(p *projection.Profile) { p.ID = "" },
		"unknown status model": func(p *projection.Profile) { p.StatusModel = "maybe" },
		"required without checks": func(p *projection.Profile) {
			p.RequiredChecks = nil
		},
		"required without inventory": func(p *projection.Profile) {
			p.Expectations = nil
		},
		"none with checks": func(p *projection.Profile) {
			p.StatusModel = projection.StatusNone
		},
		"duplicate check": func(p *projection.Profile) {
			p.RequiredChecks = []string{"c", "c"}
		},
		"duplicate expectation": func(p *projection.Profile) {
			p.Expectations = append(p.Expectations, expectation)
		},
		"bad profile digest": func(p *projection.Profile) {
			p.ProfileDigest = "sha-256:short"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Expectations = append([]projection.NativeCheckExpectation(nil), valid.Expectations...)
			candidate.RequiredChecks = append([]string(nil), valid.RequiredChecks...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid profile was accepted: %+v", candidate)
			}
		})
	}
}

func TestValidateEvidenceReportAcceptsConsistentProfileReport(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	if err := projection.ValidateEvidenceReport(report); err != nil {
		t.Fatalf("consistent report rejected: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{RequireProfile: true}); err != nil {
		t.Fatalf("complete required-profile report rejected: %v", err)
	}
}

// With a profile, dropping the lineage records cannot hide the Facts: the
// bijection is required even when the record list is empty.
func TestValidateRejectsFactWithoutLineage(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.EvidenceRecords = nil
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportFactUnbound) {
		t.Fatalf("unbound fact error = %v, want %s", err, projection.CodeReportFactUnbound)
	}
}

func TestValidateRejectsLineageArtifactMismatch(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.EvidenceRecords[0].ArtifactDigest = testDigest('b')
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportCheckBinding) {
		t.Fatalf("artifact mismatch error = %v, want %s", err, projection.CodeReportCheckBinding)
	}
}

func TestValidateRejectsForgedAssessment(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.NativeChecksComplete = true
	report.NativeCheckAssessment.Complete = false
	err := projection.ValidateEvidenceReport(report)
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportInventory) {
		t.Fatalf("forged assessment error = %v, want %s", err, projection.CodeReportInventory)
	}
}

// A profile that requires checks cannot pass final verification while its own
// report says the checks are incomplete; it can still be built and inspected.
func TestVerifyRejectsIncompleteRequiredProfile(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	artifact := testDigest('a')
	req := reportRequirementValue(t)
	profile := &projection.Profile{
		ID:             "test/profile",
		StatusModel:    projection.StatusRequired,
		RequiredChecks: []string{"native:approval"},
		Expectations: []projection.NativeCheckExpectation{
			{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: artifact},
			{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: testDigest('b')},
		},
	}
	result := nativeResult("native:approval", "approval", projection.NativeCheckSuccess, now)
	result.EvidenceDigest = artifact
	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:        "test/projector",
		Requirement:        &req,
		Facts:              []semantics.EvidenceFact{},
		NativeCheckResults: []projection.NativeCheckResult{result},
		Profile:            profile,
		Now:                now,
	})
	if err != nil {
		t.Fatalf("incomplete report should be buildable: %v", err)
	}
	if report.NativeChecksComplete {
		t.Fatal("test precondition: report should be incomplete")
	}
	if err := projection.ValidateEvidenceReport(report); err != nil {
		t.Fatalf("incomplete report should be structurally valid: %v", err)
	}
	err = projection.VerifyEvidenceReport(report, projection.ReportPolicy{})
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportIncomplete) {
		t.Fatalf("incomplete profile report passed verification: %v", err)
	}
}

func TestNotApplicableRequiresProfileAuthority(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	artifact := testDigest('a')
	req := reportRequirementValue(t)
	build := func(authority projection.Digest) error {
		profile := &projection.Profile{
			ID:                     "test/profile",
			StatusModel:            projection.StatusRequired,
			ReasonNamespace:        "native",
			RequiredChecks:         []string{"native:approval"},
			Expectations:           []projection.NativeCheckExpectation{{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: artifact}},
			NotApplicableAuthority: authority,
		}
		result := nativeResult("native:approval", "approval", projection.NativeCheckNotApplicable, now)
		result.EvidenceDigest = artifact
		result.Reason = "native:no-status-material"
		_, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:        "test/projector",
			Requirement:        &req,
			Facts:              []semantics.EvidenceFact{},
			NativeCheckResults: []projection.NativeCheckResult{result},
			Profile:            profile,
			Now:                now,
		})
		return err
	}

	if err := build(""); err == nil || !strings.Contains(err.Error(), projection.CodeReportNotApplicable) {
		t.Fatalf("unauthorized not_applicable error = %v", err)
	}
	if err := build(testDigest('f')); err == nil || !strings.Contains(err.Error(), projection.CodeReportNotApplicable) {
		t.Fatalf("wrong authority error = %v", err)
	}
	if err := build(testDigest('b')); err != nil {
		t.Fatalf("authorized not_applicable rejected: %v", err)
	}
}

// The wire form is part of the schema: digests stay "sha-256:<hex>" strings and
// freshness is a typed object, not a free-form string.  A zero decision must be
// omitted rather than serialized as an empty verdict.
func TestReportJSONUsesTypedWireForms(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, `"freshnessDecision":{"verdict":"fresh"}`) {
		t.Fatalf("freshness wire form = %s", body)
	}
	if strings.Contains(body, `"freshnessDecision":{"verdict":""}`) {
		t.Fatal("a zero freshness decision was serialized")
	}
	if !strings.Contains(body, `"evidenceDigest":"sha-256:`) {
		t.Fatal("evidence digest is not the canonical string form")
	}

	empty := nativeResult("native:approval", "approval", projection.NativeCheckUnavailable, now)
	empty.FreshnessDecision = nil
	raw, err = json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "freshnessDecision") {
		t.Fatalf("nil freshness decision was serialized: %s", raw)
	}
}

func TestBuildRejectsProfileInventoryMismatch(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	req := reportRequirementValue(t)
	profile := &projection.Profile{
		ID:             "test/profile",
		StatusModel:    projection.StatusRequired,
		RequiredChecks: []string{"native:approval"},
		Expectations:   []projection.NativeCheckExpectation{{CheckID: "native:approval", ComponentType: "approval", EvidenceDigest: testDigest('a')}},
	}
	_, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID: "test/projector",
		Requirement: &req,
		Facts:       []semantics.EvidenceFact{},
		NativeCheckExpectations: []projection.NativeCheckExpectation{
			{CheckID: "native:other", ComponentType: "approval", EvidenceDigest: testDigest('b')},
		},
		Profile: profile,
		Now:     now,
	})
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportProfile) {
		t.Fatalf("mismatched inventory error = %v, want %s", err, projection.CodeReportProfile)
	}
}

// Completeness is required by default: an incomplete report must be refused
// unless the caller explicitly accepts it.
func TestVerifyRequiresCompletenessByDefault(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	req := reportRequirementValue(t)
	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:      "test/projector",
		Requirement:      &req,
		Facts:            []semantics.EvidenceFact{},
		RequiredCheckIDs: []string{"native:approval"},
		Now:              now,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.NativeChecksComplete {
		t.Fatal("test precondition: report should be incomplete")
	}
	err = projection.VerifyEvidenceReport(report, projection.ReportPolicy{})
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportIncomplete) {
		t.Fatalf("incomplete report passed the default policy: %v", err)
	}
	if err := projection.VerifyEvidenceReport(report, projection.ReportPolicy{AllowIncomplete: true}); err != nil {
		t.Fatalf("explicit AllowIncomplete should accept: %v", err)
	}
}
