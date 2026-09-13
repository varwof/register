// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Obligation semantics — the consumer side of CLC §8.4.
//
// §8.4 makes an obligation-carrying decision an independent verdict
// (allow_unresolved) and requires the consumer to "evaluate or confirm" every
// residual constraint before acting, else deny.  It does not say what
// "confirm" means, nor what happens when the consumer does not understand an
// obligation at all.  The OASIS XACML 3.0 core specification answers that
// question normatively; the requirements are restated here in our own words and
// the specification is cited, not reproduced (see the reference below):
//
//	its §2.13 requires an enforcement point to refuse rather than proceed when
//	it cannot comprehend and carry out the obligations the governing policy
//	attaches; its §7.2.1 makes permitting conditional on the point
//	comprehending those obligations and being both able and willing to carry
//	them out.
//
// Discharge is the mechanical form of that rule: a consumer declares the
// obligation identities it understands and can and will discharge, and any
// other obligation fails closed.  It is deliberately not a general policy
// language (P2) — it is one comparison per obligation.
//
// Reference: OASIS, "eXtensible Access Control Markup Language (XACML) Version
// 3.0", core specification, sections 2.13 and 7.2.1.

package semantics

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	// ErrObligationUnknown means the decision carries an obligation whose
	// (scheme,type) identity the consumer does not understand, or whose text
	// cannot be parsed at all.  XACML §2.13 requires denying rather than
	// silently ignoring such an obligation.
	ErrObligationUnknown = errors.New("obligation_unknown")
	// ErrObligationShape means the verdict and the obligation list disagree
	// with §8.4: an allow that carries obligations, an allow_unresolved that
	// carries none, or an unknown verdict value.
	ErrObligationShape = errors.New("obligation_shape")
)

// Obligations returns an independent copy of the decision's §8.4 obligation
// list (empty for deny and for a fully evaluated allow).
func Obligations(d Decision) []string {
	return append([]string(nil), d.Unresolved...)
}

// ConstraintIdentity returns the (scheme,type) identity of a constraint — the
// granularity §8.1 recognizes constraints at ("the identity of a constraint is
// two things — the declaring scheme and the type").  A constraint that does not
// carry a parseable identity cannot be dispatched to any evaluator, so it is
// reported as an unknown obligation rather than passed along as text.
func ConstraintIdentity(c string) (string, error) {
	parts := strings.Split(c, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("%w: %q", ErrObligationUnknown, c)
	}
	// The declaring scheme uses the §3 scheme grammar, shared with capability
	// ids (P7: one definition, consumed everywhere).
	if !capabilitySchemeRE.MatchString(parts[0]) {
		return "", fmt.Errorf("%w: %q", ErrObligationUnknown, c)
	}
	// The type is the second :-delimited segment; anything that is not a plain
	// token cannot select a known evaluator.
	for _, r := range parts[1] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return "", fmt.Errorf("%w: %q", ErrObligationUnknown, c)
		}
	}
	return parts[0] + ":" + parts[1], nil
}

// ObligationIdentities returns the sorted, deduplicated (scheme,type)
// identities of the decision's obligations.  This is the granularity a consumer
// declares support at ("I understand and can discharge varwof/constraint-v1:time"),
// and the granularity §8.4's per-scheme evaluation is scoped to.
func ObligationIdentities(d Decision) ([]string, error) {
	seen := make(map[string]bool, len(d.Unresolved))
	out := make([]string, 0, len(d.Unresolved))
	for _, c := range d.Unresolved {
		id, err := ConstraintIdentity(c)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// Discharge reports whether a consumer may act on the decision.
//
// understood lists the obligation identities the consumer understands and can
// and will discharge, e.g. []string{"varwof/constraint-v1:time"}.  A decision
// with no obligations always discharges.  Every obligation on an
// allow_unresolved decision must be covered by understood; otherwise the
// consumer must deny (XACML §2.13) — an obligation it does not understand,
// cannot honour, or has not committed to is never silently dropped, and
// allow_unresolved is never read as allow.
//
// Discharge answers only "may I act at all"; confirming the obligation's actual
// value (this time window, this peer address) is the caller's separate,
// value-level step.
func Discharge(d Decision, understood []string) error {
	ids, err := ObligationIdentities(d)
	if err != nil {
		return err
	}
	if err := checkDecisionShape(d); err != nil {
		return err
	}
	if d.Verdict != VerdictAllowUR {
		return nil
	}

	have := make(map[string]bool, len(understood))
	for _, id := range understood {
		have[id] = true
	}
	for _, id := range ids {
		if !have[id] {
			return fmt.Errorf("%w: %s (the consumer must understand, can and will discharge it)", ErrObligationUnknown, id)
		}
	}
	return nil
}

// checkDecisionShape enforces the §8.4 relation between verdict and obligation
// list: unresolved is [] on deny and on a fully evaluated allow, non-empty on
// allow_unresolved, and the verdict is one of the three defined values.  A
// decision that violates the shape is refused rather than interpreted.
func checkDecisionShape(d Decision) error {
	ids, err := ObligationIdentities(d)
	if err != nil {
		return err
	}
	switch d.Verdict {
	case VerdictAllow, VerdictDeny:
		if len(ids) > 0 {
			return fmt.Errorf("%w: verdict %s carries obligations %v", ErrObligationShape, d.Verdict, ids)
		}
	case VerdictAllowUR:
		if len(ids) == 0 {
			return fmt.Errorf("%w: allow_unresolved without obligations", ErrObligationShape)
		}
	default:
		return fmt.Errorf("%w: unknown verdict %q", ErrObligationShape, d.Verdict)
	}
	return nil
}
