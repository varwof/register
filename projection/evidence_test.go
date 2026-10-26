// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

func expectation(check, component string, digest projection.Digest) projection.NativeCheckExpectation {
	return projection.NativeCheckExpectation{
		CheckID:        check,
		ComponentType:  component,
		EvidenceDigest: digest,
	}
}

func outcomeResult(check, component string, digest projection.Digest, outcome projection.NativeCheckOutcome, now time.Time) projection.NativeCheckResult {
	result := nativeResult(check, component, outcome, now)
	result.EvidenceDigest = digest
	return result
}

// testDigest builds a canonical digest from one repeated byte.  Tests only need
// stable, distinct identities, not real hashes.
func testDigest(b byte) projection.Digest {
	return projection.Digest("sha-256:" + strings.Repeat(string(b), 64))
}

// The inventory is what makes an omitted component of the same type visible: a
// second approval of the same component type must not disappear silently.
func TestAssessNativeChecksDetectsOmittedSameTypeComponent(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	expected := []projection.NativeCheckExpectation{
		expectation("status_required:approval", "approval", testDigest('a')),
		expectation("status_required:approval", "approval", testDigest('b')),
	}
	results := []projection.NativeCheckResult{
		outcomeResult("status_required:approval", "approval", testDigest('a'), projection.NativeCheckSuccess, now),
	}

	assessment := projection.AssessNativeChecks(expected, results)
	if assessment.Complete {
		t.Fatal("an omitted same-type component was reported complete")
	}
	if len(assessment.MissingExpectations) != 1 ||
		assessment.MissingExpectations[0].EvidenceDigest != testDigest('b') {
		t.Fatalf("missing expectations = %+v, want only sha-256:bob", assessment.MissingExpectations)
	}
	if len(assessment.UnexpectedResults) != 0 || len(assessment.ConflictingResults) != 0 {
		t.Fatalf("unexpected side effects: %+v", assessment)
	}
}

// An empty inventory is never complete: a profile that declares nothing has not
// shown that it reported everything.
func TestAssessNativeChecksEmptyInventoryIsIncomplete(t *testing.T) {
	if got := projection.AssessNativeChecks(nil, nil); got.Complete {
		t.Fatal("empty inventory reported complete")
	}
}

func TestAssessNativeChecksUnexpectedResult(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	expected := []projection.NativeCheckExpectation{
		expectation("oasnt:token-validity", "oasnt:approval-token", testDigest('c')),
	}
	results := []projection.NativeCheckResult{
		outcomeResult("oasnt:token-validity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckSuccess, now),
		outcomeResult("oasnt:device-integrity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckSuccess, now),
	}
	assessment := projection.AssessNativeChecks(expected, results)
	if assessment.Complete {
		t.Fatal("an undeclared component was accepted")
	}
	if len(assessment.UnexpectedResults) != 1 ||
		assessment.UnexpectedResults[0].CheckID != "oasnt:device-integrity" {
		t.Fatalf("unexpected results = %+v", assessment.UnexpectedResults)
	}
}

func TestAssessNativeChecksConflictingResult(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	expected := []projection.NativeCheckExpectation{
		expectation("oasnt:device-integrity", "oasnt:approval-token", testDigest('c')),
	}
	results := []projection.NativeCheckResult{
		outcomeResult("oasnt:device-integrity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckSuccess, now),
		outcomeResult("oasnt:device-integrity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckFailed, now),
	}
	assessment := projection.AssessNativeChecks(expected, results)
	if assessment.Complete {
		t.Fatal("two outcomes for one component were accepted")
	}
	if len(assessment.ConflictingResults) != 1 {
		t.Fatalf("conflicting results = %+v", assessment.ConflictingResults)
	}
	conflict := assessment.ConflictingResults[0]
	if conflict.CheckID != "oasnt:device-integrity" || len(conflict.Outcomes) != 2 {
		t.Fatalf("conflict = %+v", conflict)
	}
}

// A malformed inventory is rejected rather than turned into a key that can
// never match.
func TestBuildEvidenceReportRejectsMalformedExpectation(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	for name, want := range map[string]projection.NativeCheckExpectation{
		"no check id":  {ComponentType: "c", EvidenceDigest: "d"},
		"no component": {CheckID: "k", EvidenceDigest: "d"},
		"no digest":    {CheckID: "k", ComponentType: "c"},
		"blank digest": {CheckID: "k", ComponentType: "c", EvidenceDigest: " "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
				NativeCheckExpectations: []projection.NativeCheckExpectation{want},
				Now:                     now,
			}); err == nil {
				t.Fatalf("malformed expectation was accepted: %+v", want)
			}
		})
	}
}

// BuildEvidenceReport is the profile-facing assembly path: it validates the
// results, attaches the assessment, and keeps the CLC evaluation unchanged.
func TestBuildEvidenceReportCarriesObservationAndLineage(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	expected := []projection.NativeCheckExpectation{
		expectation("oasnt:token-validity", "oasnt:approval-token", testDigest('c')),
		expectation("oasnt:device-integrity", "oasnt:approval-token", testDigest('c')),
	}
	fact := semantics.EvidenceFact{
		Type: "human-authorization", Subject: "user:alice", Verified: true,
		IssuedAt: now.Add(-30 * time.Second),
	}
	req := semantics.Requirement{
		Version: "CLC-REQUIREMENT-v1", ID: "oasnt@1", Expression: "human-authorization",
	}
	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:             "oasnt/test",
		Requirement:             &req,
		RequiredNativeChecks:    []string{"oasnt:token-validity", "oasnt:device-integrity"},
		NativeCheckExpectations: expected,
		NativeCheckResults: []projection.NativeCheckResult{
			outcomeResult("oasnt:token-validity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckSuccess, now),
			outcomeResult("oasnt:device-integrity", "oasnt:approval-token", testDigest('c'), projection.NativeCheckSuccess, now),
		},
		Facts: []semantics.EvidenceFact{fact},
		Observation: &projection.ProjectedObservation{
			NativeActionDigest:   "adg-native",
			CLCActionID:          "clc-action:1:tool.call.1:jcs-sha256:AAAA",
			MappingProfileDigest: testDigest('e'),
		},
		EvidenceRecords: []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: testDigest('c'),
			ObservationID:  "adg-native",
			Fact:           &fact,
			NativeCheckIDs: []string{"oasnt:token-validity", "oasnt:device-integrity"},
		}},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.NativeChecksComplete || report.NativeCheckAssessment == nil || !report.NativeCheckAssessment.Complete {
		t.Fatalf("complete expected inventory was not complete: %+v", report.NativeCheckAssessment)
	}
	if report.Observation == nil || report.Observation.NativeActionDigest != "adg-native" ||
		report.Observation.CLCActionID == "" {
		t.Fatalf("observation was dropped: %+v", report.Observation)
	}
	if len(report.EvidenceRecords) != 1 || report.EvidenceRecords[0].Fact == nil ||
		report.EvidenceRecords[0].ArtifactDigest != testDigest('c') {
		t.Fatalf("evidence lineage was dropped: %+v", report.EvidenceRecords)
	}
	if got := report.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED", got)
	}
}

// The expectation inventory strengthens Project's completeness: a declaration
// with a component the caller did not report is incomplete even when the
// status_required rule alone would be satisfied.
func TestProjectExpectationInventoryDetectsOmission(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	results := []projection.NativeCheckResult{
		outcomeResult("status_required:a", "a", testDigest('1'), projection.NativeCheckSuccess, now),
	}
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "inventory@1",
	  "expression": "a",
	  "status_required": ["a"]
	}`

	withoutInventory, err := projection.Project([]byte(doc), projection.Options{
		Now:                now,
		RoleMap:            identityRoles("a"),
		Facts:              []semantics.EvidenceFact{},
		NativeCheckResults: results,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !withoutInventory.NativeChecksComplete {
		t.Fatal("test precondition: the status_required rule should be satisfied")
	}
	if withoutInventory.NativeCheckAssessment != nil {
		t.Fatal("an assessment was reported without a declared inventory")
	}

	withInventory, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a"),
		Facts:   []semantics.EvidenceFact{},
		NativeCheckExpectations: []projection.NativeCheckExpectation{
			expectation("status_required:a", "a", testDigest('1')),
			expectation("status_required:a", "a", testDigest('2')),
		},
		NativeCheckResults: results,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withInventory.NativeChecksComplete {
		t.Fatal("the omitted second component was not detected")
	}
	if withInventory.NativeCheckAssessment == nil ||
		len(withInventory.NativeCheckAssessment.MissingExpectations) != 1 {
		t.Fatalf("assessment = %+v", withInventory.NativeCheckAssessment)
	}
}

// The lineage record must not leak into the CLC decision: two reports with the
// same facts but different lineage produce the same Satisfaction.
func TestEvidenceLineageDoesNotChangeSatisfaction(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	req := semantics.Requirement{
		Version: "CLC-REQUIREMENT-v1", ID: "lineage@1", Expression: "human-authorization",
	}
	fact := semantics.EvidenceFact{
		Type: "human-authorization", Subject: "user:alice", Verified: true,
		IssuedAt: now.Add(-10 * time.Second),
	}
	build := func(records []projection.ProjectedEvidenceRecord) *projection.Report {
		t.Helper()
		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			Requirement:     &req,
			Facts:           []semantics.EvidenceFact{fact},
			Observation:     &projection.ProjectedObservation{NativeActionDigest: "observation"},
			EvidenceRecords: records,
			NativeCheckResults: func() []projection.NativeCheckResult {
				if len(records) == 0 {
					return nil
				}
				result := nativeResult("native:approval", "approval", projection.NativeCheckSuccess, now)
				result.EvidenceDigest = testDigest('d')
				return []projection.NativeCheckResult{result}
			}(),
			Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	plain := build(nil)
	withLineage := build([]projection.ProjectedEvidenceRecord{{
		ArtifactDigest: testDigest('d'),
		ObservationID:  "observation",
		Fact:           &fact,
		NativeCheckIDs: []string{"native:approval"},
	}})
	if plain.Satisfaction.Satisfaction().Verdict != withLineage.Satisfaction.Satisfaction().Verdict {
		t.Fatalf("lineage changed the CLC verdict: %s vs %s",
			plain.Satisfaction.Satisfaction().Verdict,
			withLineage.Satisfaction.Satisfaction().Verdict)
	}
	if !strings.HasPrefix(string(withLineage.EvidenceRecords[0].ArtifactDigest), "sha-256:") {
		t.Fatalf("record = %+v", withLineage.EvidenceRecords[0])
	}
}
