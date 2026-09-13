// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"slices"
	"testing"
)

const windowObligation = `varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`

// TestDischargeEndToEnd runs the real decision function and then the consumer
// rule: the obligation list a §8.4 decision carries is exactly what the
// consumer must declare and discharge.
func TestDischargeEndToEnd(t *testing.T) {
	dec := Authorize(
		Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}},
		Operation{ID: "std/database-v1:query:SELECT"},
	)
	if dec.Verdict != VerdictAllowUR {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, VerdictAllowUR)
	}

	if err := Discharge(dec, nil); !errors.Is(err, ErrObligationUnknown) {
		t.Errorf("no declared support: got %v, want ErrObligationUnknown", err)
	}
	if err := Discharge(dec, []string{"varwof/constraint-v1:network"}); !errors.Is(err, ErrObligationUnknown) {
		t.Errorf("wrong declared support: got %v, want ErrObligationUnknown", err)
	}
	if err := Discharge(dec, []string{"varwof/constraint-v1:time"}); err != nil {
		t.Errorf("declared support: got %v, want nil", err)
	}

	// A fully evaluated allow needs no support at all.
	clean := Authorize(Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "std/database-v1:query:SELECT"})
	if clean.Verdict != VerdictAllow {
		t.Fatalf("verdict = %q, want allow", clean.Verdict)
	}
	if err := Discharge(clean, nil); err != nil {
		t.Errorf("plain allow: got %v, want nil", err)
	}
}

func TestObligationIdentities(t *testing.T) {
	dec := Decision{
		Verdict: VerdictAllowUR,
		Unresolved: []string{
			windowObligation,
			`varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`,
			// Same identity as the first obligation, different value: the
			// identity list is deduplicated.
			`varwof/constraint-v1:time:window:[{"start":"10:00","end":"12:00"}]`,
		},
	}
	ids, err := ObligationIdentities(dec)
	if err != nil {
		t.Fatalf("ObligationIdentities: %v", err)
	}
	want := []string{"varwof/constraint-v1:network", "varwof/constraint-v1:time"}
	if !slices.Equal(ids, want) {
		t.Fatalf("identities = %v, want %v", ids, want)
	}

	// The returned list is the caller's, not the decision's storage.
	ids[0] = "mutated"
	if dec.Unresolved[0] != windowObligation {
		t.Error("ObligationIdentities aliased the decision's storage")
	}
	got := Obligations(dec)
	got[0] = "mutated"
	if dec.Unresolved[0] != windowObligation {
		t.Error("Obligations aliased the decision's storage")
	}
}

// TestDischargeShapeViolations: §8.4 fixes the shape of the obligation list per
// verdict, so anything else is refused rather than interpreted.
func TestDischargeShapeViolations(t *testing.T) {
	cases := []struct {
		name string
		dec  Decision
	}{
		{"allow with obligations", Decision{Verdict: VerdictAllow, Unresolved: []string{windowObligation}}},
		{"deny with obligations", Decision{Verdict: VerdictDeny, Reason: "capability_not_authorized", Unresolved: []string{windowObligation}}},
		{"allow_unresolved without obligations", Decision{Verdict: VerdictAllowUR}},
		{"unknown verdict", Decision{Verdict: "maybe", Unresolved: []string{windowObligation}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Discharge(tc.dec, []string{"varwof/constraint-v1:time"}); !errors.Is(err, ErrObligationShape) {
				t.Errorf("got %v, want ErrObligationShape", err)
			}
		})
	}
}

// TestDischargeUnknownObligationText: an obligation whose identity cannot be
// parsed cannot be dispatched to any evaluator, so it fails closed instead of
// being compared as opaque text.
func TestDischargeUnknownObligationText(t *testing.T) {
	for _, bad := range []string{
		"no-colon",
		"",
		":type",
		"std/database-v1:",
		"x-vendor/acme:max_rows:10", // scheme fails the §3 grammar
		"std/database-v1:bad type:1",
	} {
		dec := Decision{Verdict: VerdictAllowUR, Unresolved: []string{bad}}
		if err := Discharge(dec, []string{"varwof/constraint-v1:time"}); !errors.Is(err, ErrObligationUnknown) {
			t.Errorf("Discharge(%q): got %v, want ErrObligationUnknown", bad, err)
		}
		if _, err := ConstraintIdentity(bad); !errors.Is(err, ErrObligationUnknown) {
			t.Errorf("ConstraintIdentity(%q): got %v, want ErrObligationUnknown", bad, err)
		}
	}
}

func TestConstraintIdentityAcceptsRecognizedShapes(t *testing.T) {
	cases := map[string]string{
		"varwof/constraint-v1:max_rows:100":                        "varwof/constraint-v1:max_rows",
		"varwof/constraint-v1:time:window:[{\"start\":\"00:00\"}]": "varwof/constraint-v1:time",
		"varwof/constraint-v1:network:cidr:[\"10.0.0.0/8\"]":       "varwof/constraint-v1:network",
	}
	for in, want := range cases {
		got, err := ConstraintIdentity(in)
		if err != nil {
			t.Errorf("ConstraintIdentity(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ConstraintIdentity(%q) = %q, want %q", in, got, want)
		}
	}
}
