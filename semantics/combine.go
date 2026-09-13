// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Conflict resolution — combining independently decided sources.
//
// CLC already combines sources two ways: Intersect (§7) narrows a grant *set*
// across sources, and AuthorizeSet (§9.3) is a union *within* one source.  What
// it did not name is the rule a consumer applies when it holds several
// independently computed decisions — the AIC capability set, the principal's
// authorization, a gateway policy result — which is the PEP's actual situation.
// Each consumer previously encoded that rule ad hoc.
//
// This file pins the rule to a closed set of named algorithms, following the
// XACML 3.0 combining-algorithm family (deny-overrides / permit-overrides /
// first-applicable) rather than inventing one.  Two properties are normative:
//
//  1. **Obligations are never dropped.**  §8.4 obligations are conjunctive, so
//     combining must union them; an algorithm that would discard an obligation
//     to reach "allow" fails closed instead (ErrCombiningWouldDropObligations).
//  2. **No failure degrades toward allow.**  A missing decision, an unknown
//     algorithm, or a malformed decision never yields allow.
//
// Deliberately not implemented (needs a decision value CLC does not have):
// `only-one-applicable`, `*-unless-permit` / `*-unless-deny` need XACML's
// NotApplicable; an explicit **prohibition** (negative grant) would need a
// carrier change and is recorded as a specification proposal, not invented here.

package semantics

import (
	"errors"
	"fmt"
)

// CombiningAlgorithm names how independently decided sources are combined.
// The set is closed: an unknown name is rejected, never defaulted.
type CombiningAlgorithm string

const (
	// CombiningDenyOverrides is the default: if any source denies, the
	// operation is denied; otherwise any source carrying residual obligations
	// yields allow_unresolved with the union of those obligations; otherwise
	// allow.  It is the fail-closed choice and the one §7 already implements at
	// the grant-set level.
	CombiningDenyOverrides CombiningAlgorithm = "deny-overrides"
	// CombiningPermitOverrides: if any source allows outright, the operation
	// is allowed; else if any source denies, it is denied; else the residual
	// obligations union into allow_unresolved.  Because "allow" ignores the
	// sources that did not allow, it is refused whenever any input carries
	// obligations (that would be a fail-open drop).
	CombiningPermitOverrides CombiningAlgorithm = "permit-overrides"
	// CombiningFirstApplicable is ordered: the first decision wins, later ones
	// are not consulted.  The caller's order is the policy order, so this
	// algorithm is only appropriate where that order is itself a policy.
	CombiningFirstApplicable CombiningAlgorithm = "first-applicable"
)

// DefaultCombiningAlgorithm is the algorithm a consumer uses unless it has a
// reason to pin another one.
const DefaultCombiningAlgorithm = CombiningDenyOverrides

// Valid reports whether the algorithm is one of the defined names.
func (a CombiningAlgorithm) Valid() bool {
	switch a {
	case CombiningDenyOverrides, CombiningPermitOverrides, CombiningFirstApplicable:
		return true
	}
	return false
}

var (
	// ErrNoDecisions means there was nothing to combine.  A consumer holding no
	// decision has no authorization, so this is a refusal, not an allow.
	ErrNoDecisions = errors.New("no_decisions")
	// ErrUnknownCombiningAlgorithm means the caller named an algorithm this
	// revision does not define.
	ErrUnknownCombiningAlgorithm = errors.New("unknown_combining_algorithm")
	// ErrCombiningWouldDropObligations means the named algorithm would reach
	// allow while discarding a §8.4 obligation.  Obligations are conjunctive,
	// so the combination fails closed instead.
	ErrCombiningWouldDropObligations = errors.New("combining_would_drop_obligations")
)

// Combine applies a named combining algorithm to independently decided sources.
//
// Every decision must satisfy the §8.4 shape (checkDecisionShape); a malformed
// one fails closed.  deny-overrides reports the first denying source's reason in
// argument order, so the result is deterministic for a given input order.
func Combine(alg CombiningAlgorithm, decisions ...Decision) (Decision, error) {
	if !alg.Valid() {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownCombiningAlgorithm, alg)
	}
	if len(decisions) == 0 {
		return Decision{}, ErrNoDecisions
	}
	for i, d := range decisions {
		if err := checkDecisionShape(d); err != nil {
			return Decision{}, fmt.Errorf("decision %d: %w", i, err)
		}
	}

	switch alg {
	case CombiningFirstApplicable:
		return decisions[0], nil
	case CombiningPermitOverrides:
		return combinePermitOverrides(decisions)
	default:
		return combineDenyOverrides(decisions)
	}
}

func combineDenyOverrides(decisions []Decision) (Decision, error) {
	var obligations []string
	sawAllow := false
	for _, d := range decisions {
		switch d.Verdict {
		case VerdictDeny:
			// Deny wins outright; its reason is the reported one.
			return Decision{Verdict: VerdictDeny, Reason: d.Reason}, nil
		case VerdictAllowUR:
			obligations = append(obligations, d.Unresolved...)
		case VerdictAllow:
			sawAllow = true
		}
	}
	if len(obligations) > 0 {
		return Decision{Verdict: VerdictAllowUR, Unresolved: sortedSet(obligations)}, nil
	}
	if sawAllow {
		return Decision{Verdict: VerdictAllow}, nil
	}
	// Unreachable while the verdict set is closed (shape check above), but the
	// fallback must not be allow.
	return Decision{Verdict: VerdictDeny, Reason: ErrCapabilityNotAuth.Error()}, nil
}

func combinePermitOverrides(decisions []Decision) (Decision, error) {
	var obligations []string
	var firstDeny *Decision
	for i := range decisions {
		switch decisions[i].Verdict {
		case VerdictAllow:
			// A later allow would drop the obligations already collected.
			if len(obligations) > 0 || hasObligations(decisions[i+1:]) {
				return Decision{}, ErrCombiningWouldDropObligations
			}
			return Decision{Verdict: VerdictAllow}, nil
		case VerdictAllowUR:
			obligations = append(obligations, decisions[i].Unresolved...)
		case VerdictDeny:
			if firstDeny == nil {
				d := decisions[i]
				firstDeny = &d
			}
		}
	}
	if firstDeny != nil {
		return Decision{Verdict: VerdictDeny, Reason: firstDeny.Reason}, nil
	}
	if len(obligations) > 0 {
		return Decision{Verdict: VerdictAllowUR, Unresolved: sortedSet(obligations)}, nil
	}
	return Decision{Verdict: VerdictDeny, Reason: ErrCapabilityNotAuth.Error()}, nil
}

func hasObligations(decisions []Decision) bool {
	for _, d := range decisions {
		if len(d.Unresolved) > 0 {
			return true
		}
	}
	return false
}
