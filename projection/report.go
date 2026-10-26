// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Projection API — the language-level entry point for evidence produced in a
// foreign (non-CLC) format.
//
// CLC-E is positioned as a *projection* of another evidence model, not as a
// competing evidence language: an external artefact (e.g. an EMILIA
// EP-AEC-REQUIREMENT-v1 object) is projected into the CLC decision view, and
// only then evaluated under CLC's own invariants (three-valued satisfaction,
// eligibility from natively verified facts, and so on).  Projection never
// decides anything by itself, and everything it cannot carry is reported as a
// residual instead of being silently dropped.
//
// Consumers such as a verifier or gateway call Project/ProjectAndEvaluate; the
// projectors themselves are registered by this package (see init.go).
package projection

import (
	"fmt"
	"time"

	"github.com/varwof/register/semantics"
)

// Report is the observable result of projecting one external evidence
// document.  It is deliberately a *report*: the projected requirement and
// facts, the residuals the mapping could not carry, and (when a requirement
// was supplied or configured) the CLC satisfaction verdict.
//
// The report object is an internal, experimental implementation detail. It is
// not a CLC-E deliverable, not a published protocol, and makes no conformance
// claim; CLC-E remains the projection/evidence view.
type Report struct {
	// Version is the report schema revision.  It is part of the signed payload
	// so a consumer can refuse an unknown revision instead of guessing.
	Version string `json:"@version"`
	// Assurance is the evidence level the verifier claims (E1/E2/E3).
	Assurance AssuranceLevel `json:"assurance"`
	// ProjectorID names the mapping that recognised the document.
	ProjectorID string `json:"projectorId"`
	// Profile is the relying-party declaration this report is evaluated
	// against.  It is embedded so the report is self-describing and can be
	// signed as one object.
	Profile *Profile `json:"profile,omitempty"`
	// Verifier is the identity the report claims to have been produced by.
	// A signed report binds its signer certificate to this identity, so a
	// signature cannot be detached from the verifier it is meant to name.
	Verifier *VerifierIdentity `json:"verifier,omitempty"`
	// AppraisalTime is the instant the projection evaluated freshness at.  A
	// verifier recomputes the satisfaction at this instant, not at "now", so a
	// later verification cannot silently change a freshness decision.
	AppraisalTime *time.Time `json:"appraisalTime,omitempty"`
	// SourceFormat is the foreign format the document declared.
	SourceFormat string `json:"sourceFormat,omitempty"`
	// Meta is the projector's provenance (source format, role bridges, mapping
	// timestamps).
	Meta map[string]string `json:"meta,omitempty"`
	// Requirement is the projected CLC-REQUIREMENT-v1 view.
	Requirement *semantics.Requirement `json:"requirement,omitempty"`
	// SourceRequirementDigest is the SHA-256 over the JCS encoding of the
	// complete source requirement as received, before projection.  It keeps the
	// original relying-party bar identifiable even after rewriting.
	SourceRequirementDigest *semantics.Digest `json:"sourceRequirementDigest,omitempty"`
	// ProjectedRequirementDigest is the CLC requirement digest over the final
	// projected CLC-REQUIREMENT-v1 object, including the rewritten expression.
	ProjectedRequirementDigest *semantics.Digest `json:"projectedRequirementDigest,omitempty"`
	// NativeCheckResults records an explicit result for every required native
	// status check, including successful ones.  RequiredNativeChecks says what
	// should run; this list says what did run and what it found.  An empty
	// result list establishes nothing.
	NativeCheckResults []NativeCheckResult `json:"nativeCheckResults,omitempty"`
	// NativeCheckAssessment compares the profile's declared expectation
	// inventory with the reported results.  It is present only when the caller
	// supplied expectations.
	NativeCheckAssessment *NativeCheckAssessment `json:"nativeCheckAssessment,omitempty"`
	// NativeChecksComplete is report metadata, not a CLC verdict.  It is true
	// only when every check required by status_required has an explicit result
	// attributable to the required component and, when an expectation inventory
	// was supplied, that inventory is fully reported.  Satisfaction is never
	// final native validation while this is false.
	NativeChecksComplete bool `json:"nativeChecksComplete"`
	// Observation is the action binding the profile established natively and,
	// when pinned, the CLC ActionId it maps to.
	Observation *ProjectedObservation `json:"observation,omitempty"`
	// EvidenceRecords is the artifact → Fact lineage the profile reported.
	EvidenceRecords []ProjectedEvidenceRecord `json:"evidenceRecords,omitempty"`
	// Derivations binds each Fact to the artifact and verifier/profile that
	// produced it.  It is tamper-evident lineage, not a proof of the carrier's
	// semantics.
	Derivations []Derivation `json:"derivations,omitempty"`
	// Facts are the projected evidence facts (often empty: a requirement
	// object carries no facts of its own).
	Facts []semantics.EvidenceFact `json:"facts,omitempty"`
	// Residuals lists what the projection could not carry onto a CLC axis.
	// Empty is not the goal: an honest list is more useful than a silent drop.
	Residuals []string `json:"residuals,omitempty"`
	// RequiredNativeChecks lists obligations the native verifier or effect
	// boundary must discharge.  They are not evidence facts and cannot make a
	// CLC requirement satisfied by themselves.
	RequiredNativeChecks []string `json:"requiredNativeChecks,omitempty"`
	// RequiredCheckIDs are the check ids that must have at least one explicit
	// result.  They are plain identifiers; no prefix is interpreted.
	RequiredCheckIDs []string `json:"requiredCheckIds,omitempty"`
	// Satisfaction is the CLC verdict over the projected view.  It is nil when
	// no requirement was available to evaluate.  It is the evidence-side
	// result over eligible Facts and does not assert that the required native
	// status checks ran: when NativeChecksComplete is false, it is not final
	// native validation.
	Satisfaction *semantics.RequirementResult `json:"satisfaction,omitempty"`
}

// Options carries the pins a projection needs.  Nothing here is ever inferred
// from the document: a role bridge and the facts are both supplied by the
// relying party / native verifier that established them.
type Options struct {
	// Now is the appraisal instant (zero means the wall clock).
	Now time.Time
	// RoleMap bridges foreign component identifiers to the CLC evidence roles
	// facts are typed by.  Without an entry the foreign name is kept and a
	// residual records the missing bridge.
	RoleMap map[string]string
	// Facts are the natively verified facts the projected requirement is
	// evaluated over.  Passing nil skips evaluation unless
	// NativeCheckResults is non-empty, which still asks for an evaluation over
	// the remaining eligible facts.
	Facts []semantics.EvidenceFact
	// NativeCheckResults are the explicit native status-check results the
	// profile obtained.  Missing results are never inferred from an empty
	// result list.
	NativeCheckResults []NativeCheckResult
	// NativeCheckExpectations is the profile's expected component inventory.
	// When supplied, the report includes an assessment and completeness also
	// requires the inventory to be fully reported.
	NativeCheckExpectations []NativeCheckExpectation
}

// Project recognises and projects one external evidence document.  It returns
// an error only when no projector matches the document or the matched projector
// rejects it; an unmatched document is never an implicit allow.
func Project(raw []byte, opts Options) (*Report, error) {
	results, err := normalizeResults(opts.NativeCheckResults)
	if err != nil {
		return nil, err
	}
	p := Find(raw)
	if p == nil {
		return nil, fmt.Errorf("projection: no projector matched this document")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	view, err := p.Project(raw, Context{
		Now:     now,
		RoleMap: opts.RoleMap,
	})
	if err != nil {
		return nil, fmt.Errorf("projection: %s: %w", p.ID(), err)
	}
	return BuildEvidenceReport(EvidenceInputs{
		ProjectorID:                p.ID(),
		SourceFormat:               view.Meta["source_format"],
		Meta:                       view.Meta,
		Requirement:                view.Requirement,
		SourceRequirementDigest:    view.SourceRequirementDigest,
		ProjectedRequirementDigest: view.ProjectedRequirementDigest,
		RequiredNativeChecks:       view.RequiredNativeChecks,
		RequiredCheckIDs:           view.RequiredCheckIDs,
		NativeCheckExpectations:    opts.NativeCheckExpectations,
		NativeCheckResults:         results,
		RoleMap:                    opts.RoleMap,
		Facts:                      opts.Facts,
		Residuals:                  view.Residuals,
		Now:                        now,
	})
}

// normalizeResults validates the explicit results and rejects two records for
// the same component of the same check.
func normalizeResults(results []NativeCheckResult) ([]NativeCheckResult, error) {
	out := append([]NativeCheckResult(nil), results...)
	seen := make(map[string]bool, len(out))
	for i, result := range out {
		if err := result.validate(i); err != nil {
			return nil, fmt.Errorf("projection: %w", err)
		}
		key := resultKey(result)
		if seen[key] {
			return nil, fmt.Errorf(
				"projection: native check %q reports two results for component type %q (%s)",
				result.CheckID, result.ComponentType, result.EvidenceDigest)
		}
		seen[key] = true
	}
	return out, nil
}

// assessCompleteness combines the expectation inventory with the required-check
// coverage rule.  Both are required when both are declared.
func assessCompleteness(expected []NativeCheckExpectation, requiredChecks []string, results []NativeCheckResult) (NativeCheckAssessment, bool) {
	assessment := AssessNativeChecks(expected, results)
	complete := requiredChecksComplete(requiredChecks, results)
	if len(expected) > 0 {
		complete = complete && assessment.Complete
	}
	return assessment, complete
}

// requiredChecksComplete reports whether every required check id has at least
// one explicit result.  The id is compared literally: no carrier-specific
// prefix is special-cased.
func requiredChecksComplete(required []string, results []NativeCheckResult) bool {
	for _, checkID := range required {
		covered := false
		for _, result := range results {
			if result.CheckID == checkID {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// ProjectAndEvaluate projects a foreign document and evaluates the projected
// requirement over the supplied facts.  Facts are passed in by the caller
// because eligibility belongs to the native verifier that established them — a
// projection never invents a verified fact.
func ProjectAndEvaluate(raw []byte, facts []semantics.EvidenceFact, now time.Time) (*Report, error) {
	return Project(raw, Options{Now: now, Facts: facts})
}
