// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Evidence-side constraints — the value grammar §10 was missing.
//
// CLC §10's satisfaction algorithm says to "evaluate freshness, consumption, and
// role constraints", but §8.1 only defines the authorization-side pairs
// (max_rows / time / network): the evidence side named things it could not
// express.  This file closes that gap the same way §8.1 does — a declaring
// scheme, a two-part identity, and a closed value grammar per type:
//
//	varwof/evidence-v1:freshness:sec:300      artifact age bound at appraisal
//	varwof/evidence-v1:consumption:once       one-time authority
//	varwof/evidence-v1:quorum:distinct:2      distinct verified subjects
//	varwof/evidence-v1:exclusion:initiator    the approver may not be the initiator
//	varwof/evidence-v1:exclusion:executor     nor the executor
//
// Two rules come from the references rather than from taste:
//
//   - A requirement names an *evidence role*; the caller passes the eligible
//     facts for that role, exactly as an operation's params are the
//     authorization side's subject matter.  The core does not guess roles.
//   - Counting uses only subject identifiers that a native verifier protected.
//     The Authorization Evidence Chain profile rules out counting presenter-
//     supplied labels, identifiers taken from key encodings, or any subject
//     claim that was never verified (its section 4; cited, not reproduced), so a
//     fact that is not VERIFIED, or whose subject is empty, is ineligible here.
//
// Three-valued, like the rest of the evidence side: satisfied / violated /
// unknown, and unknown must never be read as satisfied.  `consumption` is
// always unknown here on purpose — durable consumption state belongs to the
// enforcement point (AEB §5.8), so the core reports it as a residual obligation
// instead of inventing an answer.

package semantics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// reservedEvidenceScheme declares this revision's evidence-side namespace.
	reservedEvidenceScheme = "varwof/evidence-v1"
	evidenceFreshness      = reservedEvidenceScheme + ":freshness"
	evidenceConsumption    = reservedEvidenceScheme + ":consumption"
	evidenceQuorum         = reservedEvidenceScheme + ":quorum"
	evidenceExclusion      = reservedEvidenceScheme + ":exclusion"
)

// EvidenceVerdict is the three-valued result of evaluating one evidence
// constraint.  Unknown is not satisfied (AEC §9.8: an unknown identifier
// evaluates to false).
type EvidenceVerdict string

const (
	// EvidenceSatisfied means the constraint holds over the eligible facts.
	EvidenceSatisfied EvidenceVerdict = "satisfied"
	// EvidenceViolated means it does not hold.
	EvidenceViolated EvidenceVerdict = "violated"
	// EvidenceUnknown means the core cannot decide it — an external authority
	// (the enforcement point, a status source) must, and a consumer that does
	// not obtain that answer must refuse.
	EvidenceUnknown EvidenceVerdict = "unknown"
)

// EvidenceFact is one natively verified artifact reduced to the fields the core
// may evaluate over.  Everything here must come from the artifact's own
// protected bytes or from the enforcement point's durable state; presenter
// labels are not represented at all, so they cannot be counted by accident.
type EvidenceFact struct {
	// Type is the evidence role this fact fills (e.g. "human-authorization").
	Type string
	// Subject is the integrity-protected subject identifier.  Empty means the
	// fact cannot be counted for quorum or exclusion.
	Subject string
	// IssuedAt is the protected issuance instant (UTC).  Zero means absent,
	// which fails a freshness bound rather than passing it.
	IssuedAt time.Time
	// Verified reports whether the native verifier accepted the artifact.
	Verified bool
}

// EvidenceContext carries the inputs the core does not read for itself: the
// appraisal instant and the boundary-owned identities that exclusion compares
// against (AEB §5.6 keeps those at the effect boundary).
type EvidenceContext struct {
	Now       time.Time
	Initiator string
	Executor  string
}

// EvidenceEvaluation is the result of evaluating one evidence constraint.
type EvidenceEvaluation struct {
	Constraint string          `json:"constraint"`
	Verdict    EvidenceVerdict `json:"verdict"`
	Reason     string          `json:"reason,omitempty"`
}

var (
	// ErrEvidenceConstraint means the constraint is not a recognized evidence
	// type or its value is outside the grammar (fail-closed).
	ErrEvidenceConstraint = errors.New("invalid_evidence_constraint")
	// ErrEvidenceNotCoreEvaluated means the type is recognized but its
	// evaluation belongs to an external authority.
	ErrEvidenceNotCoreEvaluated = errors.New("evidence_not_core_evaluated")
)

// ValidateEvidenceConstraint checks the closed value grammar of the four
// evidence-side types.  An unrecognized (scheme,type) is an error, never a
// silent pass — the evidence-side mirror of §8.1's unknown_constraint.
func ValidateEvidenceConstraint(c string) error {
	parts := strings.Split(c, ":")
	if len(parts) < 2 {
		return fmt.Errorf("%w: %q", ErrEvidenceConstraint, c)
	}
	switch parts[0] + ":" + parts[1] {
	case evidenceFreshness:
		if len(parts) != 4 || parts[2] != "sec" {
			return fmt.Errorf("%w: %q (want %s:freshness:sec:<n>)", ErrEvidenceConstraint, c, reservedEvidenceScheme)
		}
		n, err := strconv.Atoi(parts[3])
		if err != nil || n < 0 {
			return fmt.Errorf("%w: %q (max age must be a non-negative integer)", ErrEvidenceConstraint, c)
		}
	case evidenceConsumption:
		if len(parts) != 3 || parts[2] != "once" {
			return fmt.Errorf("%w: %q (want %s:consumption:once)", ErrEvidenceConstraint, c, reservedEvidenceScheme)
		}
	case evidenceQuorum:
		if len(parts) != 4 || parts[2] != "distinct" {
			return fmt.Errorf("%w: %q (want %s:quorum:distinct:<n>)", ErrEvidenceConstraint, c, reservedEvidenceScheme)
		}
		n, err := strconv.Atoi(parts[3])
		if err != nil || n < 2 {
			return fmt.Errorf("%w: %q (a quorum is greater than one)", ErrEvidenceConstraint, c)
		}
	case evidenceExclusion:
		if len(parts) != 3 || (parts[2] != "initiator" && parts[2] != "executor") {
			return fmt.Errorf("%w: %q (want %s:exclusion:initiator|executor)", ErrEvidenceConstraint, c, reservedEvidenceScheme)
		}
	default:
		return fmt.Errorf("%w: %q", ErrEvidenceConstraint, c)
	}
	return nil
}

// EvaluateEvidenceConstraint evaluates one evidence constraint over the
// eligible facts of a single evidence role.  A malformed constraint is an
// error; a recognized-but-external one returns EvidenceUnknown with
// ErrEvidenceNotCoreEvaluated as its reason.
func EvaluateEvidenceConstraint(c string, facts []EvidenceFact, ctx EvidenceContext) (EvidenceEvaluation, error) {
	if err := ValidateEvidenceConstraint(c); err != nil {
		return EvidenceEvaluation{}, err
	}
	parts := strings.Split(c, ":")
	out := EvidenceEvaluation{Constraint: c}

	switch parts[0] + ":" + parts[1] {
	case evidenceFreshness:
		maxAge := time.Duration(mustAtoi(parts[3])) * time.Second
		for _, f := range eligible(facts) {
			if f.IssuedAt.IsZero() {
				out.Verdict, out.Reason = EvidenceViolated, "freshness:no_issuance_time"
				return out, nil
			}
			if f.IssuedAt.After(ctx.Now) {
				out.Verdict, out.Reason = EvidenceViolated, "freshness:future_issued"
				return out, nil
			}
			if ctx.Now.Sub(f.IssuedAt) > maxAge {
				out.Verdict, out.Reason = EvidenceViolated, "freshness:stale"
				return out, nil
			}
		}
		if len(eligible(facts)) == 0 {
			// Nothing eligible to be fresh: the requirement is unfilled.
			out.Verdict, out.Reason = EvidenceViolated, "freshness:no_eligible_fact"
			return out, nil
		}
		out.Verdict = EvidenceSatisfied
		return out, nil

	case evidenceQuorum:
		threshold := mustAtoi(parts[3])
		distinct := distinctSubjects(facts)
		if len(distinct) < threshold {
			out.Verdict = EvidenceViolated
			out.Reason = fmt.Sprintf("quorum:distinct_subjects=%d<threshold=%d", len(distinct), threshold)
			return out, nil
		}
		out.Verdict = EvidenceSatisfied
		return out, nil

	case evidenceExclusion:
		var excluded string
		switch parts[2] {
		case "initiator":
			excluded = ctx.Initiator
		case "executor":
			excluded = ctx.Executor
		}
		if excluded == "" {
			// The boundary-owned identity was not supplied.  Absence is never
			// "not excluded": exclusion cannot be established, so it is unknown.
			out.Verdict, out.Reason = EvidenceUnknown, "exclusion:identity_not_supplied"
			return out, nil
		}
		for subject := range distinctSubjects(facts) {
			if subject == excluded {
				out.Verdict, out.Reason = EvidenceViolated, "exclusion:"+parts[2]+"_is_approver"
				return out, nil
			}
		}
		out.Verdict = EvidenceSatisfied
		return out, nil

	default: // evidenceConsumption
		// Durable one-time state lives at the enforcement point; the core must
		// not answer it.  Reported as a residual obligation, never as satisfied.
		out.Verdict, out.Reason = EvidenceUnknown, ErrEvidenceNotCoreEvaluated.Error()
		return out, nil
	}
}

// CoreEvaluatesEvidenceConstraint reports whether this revision has an evaluator
// for the constraint, mirroring coreEvaluatesConstraint on the authorization
// side.  Unrecognized constraints report false.
func CoreEvaluatesEvidenceConstraint(c string) bool {
	if err := ValidateEvidenceConstraint(c); err != nil {
		return false
	}
	parts := strings.Split(c, ":")
	return parts[0]+":"+parts[1] != evidenceConsumption
}

// EvidenceFactsOfRole selects the facts filling one evidence role.  A
// constraint is evaluated over exactly one role's facts (the evidence-side
// analogue of an operation's params being the subject matter of an
// authorization constraint), so callers scope first and evaluate second.
func EvidenceFactsOfRole(facts []EvidenceFact, role string) []EvidenceFact {
	out := make([]EvidenceFact, 0, len(facts))
	for _, f := range facts {
		if f.Type == role {
			out = append(out, f)
		}
	}
	return out
}

// eligible keeps the facts a verifier actually established (AEC §9.4.f: only
// eligible components contribute).
func eligible(facts []EvidenceFact) []EvidenceFact {
	out := make([]EvidenceFact, 0, len(facts))
	for _, f := range facts {
		if f.Verified {
			out = append(out, f)
		}
	}
	return out
}

// distinctSubjects counts integrity-protected subject identifiers.  An empty
// subject is ineligible: a fact whose subject the verifier did not establish
// must not be counted (AEC §4 role_constraints).
func distinctSubjects(facts []EvidenceFact) map[string]bool {
	out := make(map[string]bool)
	for _, f := range eligible(facts) {
		if f.Subject == "" {
			continue
		}
		out[f.Subject] = true
	}
	return out
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s) // ValidateEvidenceConstraint already accepted it
	return n
}
