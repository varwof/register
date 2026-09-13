// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"slices"
	"testing"
)

const netObligation = `varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`

func allow() Decision                 { return Decision{Verdict: VerdictAllow} }
func deny() Decision                  { return Decision{Verdict: VerdictDeny, Reason: "capability_not_authorized"} }
func unresolved(o ...string) Decision { return Decision{Verdict: VerdictAllowUR, Unresolved: o} }

// TestDenyOverridesIsFailClosed walks the verdict lattice: a deny anywhere wins,
// residual obligations survive as allow_unresolved, and only an all-allow set
// yields allow.
func TestDenyOverridesIsFailClosed(t *testing.T) {
	ob := []string{windowObligation}

	cases := []struct {
		name        string
		in          []Decision
		wantVerdict string
		wantReason  string
		wantUnres   []string
	}{
		{"all allow", []Decision{allow(), allow(), allow()}, VerdictAllow, "", nil},
		{"one deny", []Decision{allow(), deny(), allow()}, VerdictDeny, "capability_not_authorized", nil},
		{"deny before unresolved", []Decision{unresolved(ob[0]), deny()}, VerdictDeny, "capability_not_authorized", nil},
		{"deny after unresolved", []Decision{deny(), unresolved(ob[0])}, VerdictDeny, "capability_not_authorized", nil},
		{"allow plus unresolved", []Decision{allow(), unresolved(ob[0])}, VerdictAllowUR, "", ob},
		{"unresolved union", []Decision{unresolved(ob[0]), unresolved(netObligation)}, VerdictAllowUR, "", []string{netObligation, ob[0]}},
		{"duplicate obligation collapses", []Decision{unresolved(ob[0]), unresolved(ob[0])}, VerdictAllowUR, "", ob},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Combine(CombiningDenyOverrides, tc.in...)
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if got.Verdict != tc.wantVerdict || got.Reason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", got.Verdict, got.Reason, tc.wantVerdict, tc.wantReason)
			}
			if !slices.Equal(got.Unresolved, tc.wantUnres) {
				t.Fatalf("unresolved = %v, want %v", got.Unresolved, tc.wantUnres)
			}
		})
	}
}

// TestDenyOverridesIsOrderIndependentExceptForTheReason: the verdict and the
// obligation set do not depend on argument order; only which deny's reason is
// reported does (deterministically, the first one).
func TestDenyOverridesIsOrderIndependent(t *testing.T) {
	in := [][]Decision{
		{allow(), unresolved(windowObligation), allow()},
		{allow(), allow(), unresolved(windowObligation)},
		{unresolved(windowObligation), allow(), allow()},
	}
	var first Decision
	for i, set := range in {
		got, err := Combine(CombiningDenyOverrides, set...)
		if err != nil {
			t.Fatalf("Combine(%v): %v", set, err)
		}
		if got.Verdict != VerdictAllowUR || !slices.Equal(got.Unresolved, []string{windowObligation}) {
			t.Fatalf("permutation %d = %+v, want allow_unresolved with the window obligation", i, got)
		}
		if i == 0 {
			first = got
		} else if got.Verdict != first.Verdict || !slices.Equal(got.Unresolved, first.Unresolved) {
			t.Errorf("permutation %d differs: %+v vs %+v", i, got, first)
		}
	}
}

// The first denying source's reason is reported, in argument order.
func TestDenyOverridesReportsFirstDenyReason(t *testing.T) {
	a := Decision{Verdict: VerdictDeny, Reason: "params_exceed_grant"}
	b := Decision{Verdict: VerdictDeny, Reason: "different_namespace"}
	got, err := Combine(CombiningDenyOverrides, a, b)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if got.Reason != "params_exceed_grant" {
		t.Errorf("reason = %q, want the first deny's reason", got.Reason)
	}
}

// permit-overrides is available but must never silently drop an obligation.
func TestPermitOverrides(t *testing.T) {
	got, err := Combine(CombiningPermitOverrides, deny(), allow())
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if got.Verdict != VerdictAllow {
		t.Errorf("deny+allow = %q, want allow under permit-overrides", got.Verdict)
	}

	if _, err := Combine(CombiningPermitOverrides, deny(), allow(), unresolved(windowObligation)); !errors.Is(err, ErrCombiningWouldDropObligations) {
		t.Errorf("allow alongside an obligation: got %v, want ErrCombiningWouldDropObligations", err)
	}
	// Also fail-closed when the allow comes last.
	if _, err := Combine(CombiningPermitOverrides, unresolved(windowObligation), allow()); !errors.Is(err, ErrCombiningWouldDropObligations) {
		t.Errorf("obligation then allow: got %v, want ErrCombiningWouldDropObligations", err)
	}

	// Without an allow: deny beats unresolved, else unresolved unions.
	got, err = Combine(CombiningPermitOverrides, unresolved(windowObligation), deny())
	if err != nil || got.Verdict != VerdictDeny {
		t.Fatalf("unresolved+deny = %+v (%v), want deny", got, err)
	}
	got, err = Combine(CombiningPermitOverrides, unresolved(windowObligation), unresolved(netObligation))
	if err != nil || got.Verdict != VerdictAllowUR || len(got.Unresolved) != 2 {
		t.Fatalf("unresolved+unresolved = %+v (%v), want allow_unresolved with both", got, err)
	}
}

func TestFirstApplicableIsOrdered(t *testing.T) {
	got, err := Combine(CombiningFirstApplicable, deny(), allow())
	if err != nil || got.Verdict != VerdictDeny {
		t.Fatalf("deny first = %+v (%v), want deny", got, err)
	}
	got, err = Combine(CombiningFirstApplicable, unresolved(windowObligation), deny())
	if err != nil || got.Verdict != VerdictAllowUR {
		t.Fatalf("unresolved first = %+v (%v), want allow_unresolved", got, err)
	}
}

func TestCombineRejectsBadInput(t *testing.T) {
	if _, err := Combine(CombiningDenyOverrides); !errors.Is(err, ErrNoDecisions) {
		t.Errorf("no decisions: got %v, want ErrNoDecisions", err)
	}
	if _, err := Combine("permit-unless-deny", allow()); !errors.Is(err, ErrUnknownCombiningAlgorithm) {
		t.Errorf("unknown algorithm: got %v, want ErrUnknownCombiningAlgorithm", err)
	}
	if _, err := Combine(CombiningDenyOverrides, Decision{Verdict: VerdictAllow, Unresolved: []string{windowObligation}}); !errors.Is(err, ErrObligationShape) {
		t.Errorf("malformed decision: got %v, want ErrObligationShape", err)
	}
	if DefaultCombiningAlgorithm != CombiningDenyOverrides {
		t.Errorf("default = %q, want deny-overrides", DefaultCombiningAlgorithm)
	}
	if CombiningAlgorithm("").Valid() {
		t.Error("empty algorithm must be invalid")
	}
}

// TestCombineRealDecisions wires the real decision function into the combining
// rule: two independently decided sources (one bounded, one not) and then the
// consumer obligation check.
func TestCombineRealDecisions(t *testing.T) {
	bounded := Authorize(
		Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}},
		Operation{ID: "std/database-v1:query:SELECT"},
	)
	plain := Authorize(
		Grant{ID: "std/database-v1:query:SELECT"},
		Operation{ID: "std/database-v1:query:SELECT"},
	)
	absent := Authorize(Grant{}, Operation{ID: "std/database-v1:query:SELECT"})

	combined, err := Combine(DefaultCombiningAlgorithm, bounded, plain)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if combined.Verdict != VerdictAllowUR {
		t.Fatalf("combined = %+v, want allow_unresolved", combined)
	}
	if err := Discharge(combined, nil); !errors.Is(err, ErrObligationUnknown) {
		t.Errorf("combine must not launder obligations away: got %v", err)
	}
	if err := Discharge(combined, []string{"varwof/constraint-v1:time"}); err != nil {
		t.Errorf("declared support: %v", err)
	}

	denied, err := Combine(DefaultCombiningAlgorithm, bounded, plain, absent)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if denied.Verdict != VerdictDeny || denied.Reason != "capability_not_authorized" {
		t.Fatalf("denied = %+v, want deny/capability_not_authorized", denied)
	}
}
