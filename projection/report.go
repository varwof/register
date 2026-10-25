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
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// Report is the observable result of projecting one external evidence
// document.  It is deliberately a *report*: the projected requirement and
// facts, the residuals the mapping could not carry, and (when a requirement
// was supplied or configured) the CLC satisfaction verdict.
type Report struct {
	// ProjectorID names the mapping that recognised the document.
	ProjectorID string `json:"projectorId"`
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
	// UnavailableNativeInputs records native inputs that produced no eligible
	// Fact.  It is report evidence, not an alternative verdict: a missing input
	// never becomes "allow_unresolved", and remains visible when another OR
	// branch satisfies the requirement.
	UnavailableNativeInputs []NativeUnavailability `json:"unavailableNativeInputs,omitempty"`
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
	// Satisfaction is the CLC verdict over the projected view.  It is nil when
	// no requirement was available to evaluate.  It does not assert that the
	// RequiredNativeChecks succeeded; callers must discharge those checks before
	// treating the overall native evaluation as complete.
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
	// UnavailableNativeInputs is non-empty, which still asks for an evaluation
	// over the remaining eligible facts.
	Facts []semantics.EvidenceFact
	// UnavailableNativeInputs records native inputs the verifier could not
	// supply or could not verify.  They contribute no facts; the reason is
	// carried into the report so an eligible sibling OR branch can satisfy the
	// requirement without hiding the unavailable branch.
	UnavailableNativeInputs []NativeUnavailability
}

// Project recognises and projects one external evidence document.  It returns
// an error only when no projector matches the document or the matched projector
// rejects it; an unmatched document is never an implicit allow.
func Project(raw []byte, opts Options) (*Report, error) {
	for i, unavailable := range opts.UnavailableNativeInputs {
		if strings.TrimSpace(unavailable.Type) == "" {
			return nil, fmt.Errorf("projection: unavailable native input %d has no type", i)
		}
		if strings.TrimSpace(unavailable.Reason) == "" {
			return nil, fmt.Errorf("projection: unavailable native input %q has no reason", unavailable.Type)
		}
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
	rep := &Report{
		ProjectorID:                p.ID(),
		SourceFormat:               view.Meta["source_format"],
		Meta:                       view.Meta,
		Requirement:                view.Requirement,
		SourceRequirementDigest:    view.SourceRequirementDigest,
		ProjectedRequirementDigest: view.ProjectedRequirementDigest,
		UnavailableNativeInputs:    opts.UnavailableNativeInputs,
		Facts:                      view.Facts,
		Residuals:                  view.Residuals,
		RequiredNativeChecks:       view.RequiredNativeChecks,
	}
	// A facts slice (even an empty one) asks for evaluation.  So does a
	// report of unavailable native inputs: the caller has supplied the native
	// outcome, so the projected expression must be evaluated over whatever
	// eligible facts remain.
	if rep.Requirement != nil && (opts.Facts != nil || len(opts.UnavailableNativeInputs) != 0) {
		sat, err := semantics.EvaluateRequirement(*rep.Requirement, opts.Facts, semantics.EvidenceContext{Now: now})
		if err != nil {
			return nil, fmt.Errorf("projection: evaluate projected requirement: %w", err)
		}
		rep.Satisfaction = &sat
	}
	return rep, nil
}

// ProjectAndEvaluate projects a foreign document and evaluates the projected
// requirement over the supplied facts.  Facts are passed in by the caller
// because eligibility belongs to the native verifier that established them — a
// projection never invents a verified fact.
func ProjectAndEvaluate(raw []byte, facts []semantics.EvidenceFact, now time.Time) (*Report, error) {
	return Project(raw, Options{Now: now, Facts: facts})
}
