// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Profile-neutral evidence report machinery: what a native profile observed,
// which native artifact produced which CLC Fact, and whether the profile's
// declared check inventory was actually reported.
//
// Everything in this file is report/profile metadata.  None of it changes a
// CLC decision: Facts stay semantics.EvidenceFact and the CLC expression is
// evaluated exactly as before.
package projection

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// ProjectedObservation is the action binding a profile established natively
// and, when a pinned action-mapping profile exists, the CLC ActionId it maps
// to.
//
// A native action digest (OASNT `adg`, a CAID value, ...) is NOT a CLC
// ActionId.  They are related only by an explicit mapping profile; when no
// mapping is pinned, CLCACtionID stays empty and the native digest is recorded
// as a residual input of the report.
type ProjectedObservation struct {
	// NativeActionDigest is the profile's own action digest over its canonical
	// action representation.
	NativeActionDigest string `json:"nativeActionDigest,omitempty"`
	// CLCACtionID is the CLC action identifier in its string form
	// (clc-action:1:...), present only when a pinned mapping produced one.
	CLCActionID string `json:"clcActionId,omitempty"`
	// ActionType is the action type the observation is bound to.
	ActionType string `json:"actionType,omitempty"`
	// MaterialFields is the material field set the identity was computed over.
	MaterialFields []string `json:"materialFields,omitempty"`
	// MaterialProfileID names the material-field/action-type profile that
	// declared MaterialFields.
	MaterialProfileID string `json:"materialProfileId,omitempty"`
	// MappingProfileDigest pins the native-to-CLC mapping profile.  Empty means
	// no mapping was applied, never an implicit identity mapping.
	MappingProfileDigest Digest `json:"mappingProfileDigest,omitempty"`
}

// ProjectedEvidenceRecord is the lineage between one native artifact and the
// CLC Fact it produced (when it produced one).  It answers "which artifact,
// observed as which action, gated by which native checks, produced this Fact".
//
// The Fact remains CLC's own EvidenceFact; this record is report metadata.
type ProjectedEvidenceRecord struct {
	// ArtifactDigest is the digest of the native artifact as received.
	ArtifactDigest Digest `json:"artifactDigest"`
	// NativeRecordDigest is an optional digest computed by the native profile
	// over its own record form.
	NativeRecordDigest Digest `json:"nativeRecordDigest,omitempty"`
	// ObservationID links the record to the observation it was evaluated
	// against (for example the native action digest).
	ObservationID string `json:"observationId,omitempty"`
	// Fact is the projected Fact, nil when no Fact was eligible.
	Fact *semantics.EvidenceFact `json:"fact,omitempty"`
	// FactIndex identifies the entry of Report.Facts this record produced.
	// Value equality is not an identity: two identical facts from different
	// artifacts must be distinguishable, and only an index does that without
	// changing the CLC fact object.
	FactIndex *int `json:"factIndex,omitempty"`
	// NativeCheckIDs lists the native checks that gated this Fact.
	NativeCheckIDs []string `json:"nativeCheckIds,omitempty"`
	// RelationTupleDigest is the canonical relation tuple digest for a derived
	// relation Fact, when the profile emits one.
	RelationTupleDigest Digest `json:"relationTupleDigest,omitempty"`
}

// NativeCheckExpectation declares one component a profile expects to report.
// It is the expected inventory: without it, completeness can only be checked
// against the results the caller happened to submit.
type NativeCheckExpectation struct {
	// CheckID is the native check identifier.
	CheckID string `json:"checkId"`
	// ComponentType is the native component type the check runs over.
	ComponentType string `json:"componentType"`
	// EvidenceDigest is the per-component identity (artifact digest or another
	// stable identity when several components share one type).
	EvidenceDigest Digest `json:"evidenceDigest"`
}

func (e NativeCheckExpectation) key() string {
	return e.CheckID + "\x00" + e.ComponentType + "\x00" + string(e.EvidenceDigest)
}

func resultKey(r NativeCheckResult) string {
	return r.CheckID + "\x00" + r.ComponentType + "\x00" + string(r.EvidenceDigest)
}

// NativeCheckAssessment is the comparison between the declared expectation
// inventory and the results actually reported.  It is report metadata, not a
// CLC verdict.
type NativeCheckAssessment struct {
	// Complete is true only when the inventory is non-empty, every expected
	// component has exactly one result, and unrereported/extra/conflicting
	// results are absent.
	Complete bool `json:"complete"`
	// MissingExpectations are expected components with no result.
	MissingExpectations []NativeCheckExpectation `json:"missingExpectations,omitempty"`
	// UnexpectedResults are results for components the inventory does not
	// declare.
	UnexpectedResults []NativeCheckResult `json:"unexpectedResults,omitempty"`
	// ConflictingResults are components with more than one outcome.  They are
	// never merged into a single answer.
	ConflictingResults []NativeCheckConflict `json:"conflictingResults,omitempty"`
}

// NativeCheckConflict is one component reported with more than one outcome.
type NativeCheckConflict struct {
	CheckID        string   `json:"checkId"`
	ComponentType  string   `json:"componentType"`
	EvidenceDigest Digest   `json:"evidenceDigest,omitempty"`
	Outcomes       []string `json:"outcomes"`
}

// AssessNativeChecks compares the expected inventory with the explicit
// results.  It is deliberately independent of CLC requirement evaluation and
// does not validate the results themselves: callers that accept untrusted
// input run NativeCheckResult.validate through Project/BuildEvidenceReport
// first.
//
// An empty inventory is never "complete": a profile that declares no expected
// components has not shown that it reported them all.
func AssessNativeChecks(expected []NativeCheckExpectation, results []NativeCheckResult) NativeCheckAssessment {
	outcomes := make(map[string]map[string]bool, len(results))
	for _, result := range results {
		key := resultKey(result)
		if outcomes[key] == nil {
			outcomes[key] = make(map[string]bool, 1)
		}
		outcomes[key][string(result.Outcome)] = true
	}

	assessment := NativeCheckAssessment{}
	expectedKeys := make(map[string]bool, len(expected))
	for _, want := range expected {
		key := want.key()
		if expectedKeys[key] {
			// A duplicated expectation is an inventory defect, not a second
			// component.  Surface it as missing so the caller fixes the
			// inventory instead of silently deduplicating.
			assessment.MissingExpectations = append(assessment.MissingExpectations, want)
			continue
		}
		expectedKeys[key] = true
		if len(outcomes[key]) == 0 {
			assessment.MissingExpectations = append(assessment.MissingExpectations, want)
		}
	}
	for key, seen := range outcomes {
		if len(seen) > 1 {
			assessment.ConflictingResults = append(assessment.ConflictingResults,
				conflictFrom(key, seen))
		}
	}
	for _, result := range results {
		if len(expectedKeys) > 0 && !expectedKeys[resultKey(result)] {
			assessment.UnexpectedResults = append(assessment.UnexpectedResults, result)
		}
	}
	sort.Slice(assessment.ConflictingResults, func(i, j int) bool {
		return assessment.ConflictingResults[i].CheckID < assessment.ConflictingResults[j].CheckID
	})
	assessment.Complete = len(expected) > 0 &&
		len(assessment.MissingExpectations) == 0 &&
		len(assessment.UnexpectedResults) == 0 &&
		len(assessment.ConflictingResults) == 0
	return assessment
}

// conflictFrom rebuilds the component identity from an assessment key.  The
// parts are NUL-separated and none of the identifiers can contain NUL.
func conflictFrom(key string, outcomes map[string]bool) NativeCheckConflict {
	parts := strings.Split(key, "\x00")
	names := make([]string, 0, len(outcomes))
	for name := range outcomes {
		names = append(names, name)
	}
	sort.Strings(names)
	conflict := NativeCheckConflict{Outcomes: names}
	if len(parts) == 3 {
		conflict.CheckID = parts[0]
		conflict.ComponentType = parts[1]
		conflict.EvidenceDigest = Digest(parts[2])
	}
	return conflict
}

// EvidenceInputs is the profile-facing assembly input for a report.  A
// projector fills it from a foreign document; a profile that has no foreign
// requirement document (an OASNT approval token, for example) fills it
// directly.
type EvidenceInputs struct {
	ProjectorID                string
	SourceFormat               string
	Meta                       map[string]string
	Requirement                *semantics.Requirement
	SourceRequirementDigest    *semantics.Digest
	ProjectedRequirementDigest *semantics.Digest
	RequiredNativeChecks       []string
	// RequiredCheckIDs are the check ids that must have explicit results.
	// Profiles merge their own RequiredChecks into this set.
	RequiredCheckIDs        []string
	NativeCheckExpectations []NativeCheckExpectation
	NativeCheckResults      []NativeCheckResult
	// Profile is the relying-party declaration the report is evaluated
	// against.  When set it is embedded in the report and its required checks
	// and expectation inventory are enforced.
	Profile *Profile
	// Verifier is the identity the report claims to have been produced by.  A
	// signed report binds its signer to this identity.
	Verifier *VerifierIdentity
	// Assurance is the evidence level the report claims.  Empty means E2 when
	// derivations are generated, otherwise E1.
	Assurance AssuranceLevel
	// CarrierID names the native carrier for generated derivation records.
	// When set, BuildEvidenceReport emits one derivation per projected Fact.
	CarrierID       string
	RoleMap         map[string]string
	Facts           []semantics.EvidenceFact
	Observation     *ProjectedObservation
	EvidenceRecords []ProjectedEvidenceRecord
	Residuals       []string
	Now             time.Time
}

// BuildEvidenceReport assembles the report for a profile that supplies its own
// requirement, facts and native-check material.  It applies the same result
// validation, completeness and evaluation rules as Project.
func BuildEvidenceReport(in EvidenceInputs) (*Report, error) {
	results, err := normalizeResults(in.NativeCheckResults)
	if err != nil {
		return nil, err
	}
	requiredDisplay := in.RequiredNativeChecks
	requiredIDs := append([]string(nil), in.RequiredCheckIDs...)
	expectations := in.NativeCheckExpectations
	if in.Profile != nil {
		if err := in.Profile.Validate(); err != nil {
			return nil, err
		}
		requiredIDs = unionStrings(requiredIDs, in.Profile.RequiredChecks)
		if len(requiredDisplay) == 0 {
			requiredDisplay = append([]string(nil), in.Profile.RequiredChecks...)
		}
		if len(expectations) == 0 {
			expectations = in.Profile.Expectations
		} else if !sameExpectations(expectations, in.Profile.Expectations) {
			return nil, reportFail(CodeReportProfile,
				"expectation inventory differs from profile %q", in.Profile.ID)
		}
	}
	for i, want := range expectations {
		if err := want.validate(i); err != nil {
			return nil, reportFail(CodeReportShape, "%s", err)
		}
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rep := &Report{
		ProjectorID:                in.ProjectorID,
		SourceFormat:               in.SourceFormat,
		Meta:                       in.Meta,
		Requirement:                in.Requirement,
		SourceRequirementDigest:    in.SourceRequirementDigest,
		ProjectedRequirementDigest: in.ProjectedRequirementDigest,
		NativeCheckResults:         results,
		Observation:                in.Observation,
		EvidenceRecords:            in.EvidenceRecords,
		Facts:                      in.Facts,
		Residuals:                  in.Residuals,
		RequiredNativeChecks:       requiredDisplay,
		RequiredCheckIDs:           requiredIDs,
		Profile:                    in.Profile,
		Verifier:                   in.Verifier,
		AppraisalTime:              &now,
	}
	assessment, complete := assessCompleteness(expectations, requiredIDs, results)
	if len(expectations) > 0 {
		rep.NativeCheckAssessment = &assessment
	}
	rep.NativeChecksComplete = complete
	if rep.Requirement != nil && (in.Facts != nil || len(results) != 0) {
		sat, err := semantics.EvaluateRequirement(*rep.Requirement, in.Facts, semantics.EvidenceContext{Now: now})
		if err != nil {
			return nil, fmt.Errorf("projection: evaluate projected requirement: %w", err)
		}
		rep.Satisfaction = &sat
	}
	// A record that names a fact but no index is unambiguous only when the fact
	// value appears once in the report.  Duplicate values must be indexed by the
	// caller, because value equality cannot say which artifact produced which.
	for i := range rep.EvidenceRecords {
		record := &rep.EvidenceRecords[i]
		if record.Fact == nil || record.FactIndex != nil {
			continue
		}
		index, err := uniqueFactIndex(rep.Facts, *record.Fact)
		if err != nil {
			return nil, reportFail(CodeReportFactUnbound, "evidence record %d: %s", i, err)
		}
		record.FactIndex = &index
	}
	if in.CarrierID != "" && len(rep.Derivations) == 0 {
		if in.Verifier == nil || in.Verifier.VerifierProfileDigest.Empty() {
			return nil, reportFail(CodeReportDerivation,
				"carrierId requires a verifier profile digest")
		}
		mapping := Digest("")
		if in.Observation != nil {
			mapping = in.Observation.MappingProfileDigest
		}
		for i := range rep.EvidenceRecords {
			record := &rep.EvidenceRecords[i]
			if record.Fact == nil || record.FactIndex == nil {
				continue
			}
			binding, err := FactBindingDigest(*record.Fact, record.ArtifactDigest)
			if err != nil {
				return nil, reportFail(CodeReportDerivation, "evidence record %d: %s", i, err)
			}
			rep.Derivations = append(rep.Derivations, Derivation{
				CarrierID:             in.CarrierID,
				ArtifactDigest:        record.ArtifactDigest,
				VerifierProfileDigest: in.Verifier.VerifierProfileDigest,
				MappingProfileDigest:  mapping,
				FactIndex:             *record.FactIndex,
				FactDigest:            binding,
				NativeCheckIDs:        append([]string(nil), record.NativeCheckIDs...),
			})
		}
	}
	assurance := in.Assurance
	if assurance == "" {
		if len(rep.Derivations) > 0 {
			assurance = AssuranceE2
		} else {
			assurance = AssuranceE1
		}
	}
	if !assurance.Valid() {
		return nil, reportFail(CodeReportShape, "assurance %q is not E1|E2|E3", assurance)
	}
	if assurance.rank() >= AssuranceE2.rank() && len(rep.Derivations) == 0 {
		return nil, reportFail(CodeReportPolicy,
			"assurance %s requires derivation records", assurance)
	}
	rep.Version = ReportVersion
	rep.Assurance = assurance
	if err := ValidateEvidenceReport(rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// uniqueFactIndex returns the index of fact when it appears exactly once.
func uniqueFactIndex(facts []semantics.EvidenceFact, fact semantics.EvidenceFact) (int, error) {
	key := factKey(fact)
	found := -1
	for i, candidate := range facts {
		if factKey(candidate) != key {
			continue
		}
		if found != -1 {
			return 0, fmt.Errorf("fact value appears more than once; set factIndex explicitly")
		}
		found = i
	}
	if found == -1 {
		return 0, fmt.Errorf("fact is not present in the report")
	}
	return found, nil
}

// unionStrings returns the set union, preserving first-seen order.
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, value := range append(append([]string(nil), a...), b...) {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// sameStrings compares two string sets, ignoring order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}

// sameExpectations compares two inventories as sets.
func sameExpectations(a, b []NativeCheckExpectation) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, e := range a {
		seen[e.key()]++
	}
	for _, e := range b {
		if seen[e.key()] == 0 {
			return false
		}
		seen[e.key()]--
	}
	return true
}
