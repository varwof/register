// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"strings"
	"testing"

	pki "github.com/varwof/types"
)

func mustConstraintString(t *testing.T, scheme, id string, params []byte) string {
	t.Helper()
	s, err := ConstraintString(pki.Capability{SchemeId: scheme, CapabilityId: id, Parameters: params})
	if err != nil {
		t.Fatalf("ConstraintString(%q,%q): %v", scheme, id, err)
	}
	return s
}

// canonical window forms used across the tests (split same-day form, CLC-1.3).
const (
	w09001800   = `varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`
	w1012       = `varwof/constraint-v1:time:window:[{"start":"10:00","end":"12:00"}]`
	w08002000   = `varwof/constraint-v1:time:window:[{"start":"08:00","end":"20:00"}]`
	w1830       = `varwof/constraint-v1:time:window:[{"start":"18:00","end":"18:30"}]`
	wMidnight   = `varwof/constraint-v1:time:window:[{"start":"22:00","end":"00:00"}]`
	wMidnightIn = `varwof/constraint-v1:time:window:[{"start":"23:00","end":"00:00"}]`
)

func TestConstraintString(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		id     string
		params []byte
		want   string
	}{
		{"max_rows", "varwof/constraint-v1", "max_rows", []byte(`10`), "varwof/constraint-v1:max_rows:10"},
		{"time window", "varwof/constraint-v1", "time:window", []byte(`[{"start":"09:00","end":"18:00"}]`), w09001800},
		{"cidr", "varwof/constraint-v1", "network:cidr", []byte(`["192.0.2.0/24"]`), `varwof/constraint-v1:network:cidr:["192.0.2.0/24"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustConstraintString(t, c.scheme, c.id, c.params)
			if got != c.want {
				t.Fatalf("string = %q, want %q", got, c.want)
			}
		})
	}
}

func TestConstraintStringRejectsForeignScheme(t *testing.T) {
	if _, err := ConstraintString(pki.Capability{SchemeId: "payments/quota-v1", CapabilityId: "daily", Parameters: []byte(`1000000`)}); err == nil {
		t.Fatal("foreign constraint scheme must fail closed")
	}
	if _, err := ConstraintString(pki.Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "time:window", Parameters: []byte(`3600`)}); err == nil {
		t.Fatal("out-of-grammar value must fail closed")
	}
}

// Legacy constraint aliases accepted elsewhere on the wire (core's AIC writer,
// the verifier glue) must canonicalise to varwof/constraint-v1 here too, so a
// principal certificate written with an alias is not rejected by the subset
// check while every other layer understood it.
func TestConstraintStringAcceptsLegacySchemes(t *testing.T) {
	for _, scheme := range []string{"constraint", "constraint-v1", "varwof/constraint-v1"} {
		got := mustConstraintString(t, scheme, "time:window", []byte(`[{"start":"09:00","end":"18:00"}]`))
		if got != w09001800 {
			t.Errorf("scheme %q: string = %q, want %q", scheme, got, w09001800)
		}
	}
}

// CanonicalConstraint rewrites legacy schemes to varwof/constraint-v1 and
// leaves foreign schemes untouched.
func TestCanonicalConstraint(t *testing.T) {
	for _, scheme := range []string{"constraint", "constraint-v1", "varwof/constraint-v1"} {
		in := pki.Capability{SchemeId: scheme, CapabilityId: "time:window"}
		if got := CanonicalConstraint(in); got.SchemeId != "varwof/constraint-v1" {
			t.Errorf("scheme %q: got %q, want varwof/constraint-v1", scheme, got.SchemeId)
		}
	}
	foreign := pki.Capability{SchemeId: "payments/quota-v1", CapabilityId: "daily"}
	if got := CanonicalConstraint(foreign); got.SchemeId != foreign.SchemeId {
		t.Errorf("foreign scheme rewritten to %q", got.SchemeId)
	}
	if got := CanonicalConstraints(nil); got != nil {
		t.Errorf("nil input must stay nil, got %v", got)
	}
}

func TestSubsetConstraints(t *testing.T) {
	cases := []struct {
		name      string
		principal []string
		requested []string
		want      bool
		wantErr   bool
	}{
		{"empty principal is no boundary", nil, []string{w09001800}, true, false},
		{"empty requested is full inheritance", []string{w09001800}, nil, true, false},
		{"identical time window", []string{w09001800}, []string{w09001800}, true, false},
		{"requested inside principal", []string{w09001800}, []string{w1012}, true, false},
		{"requested beyond principal", []string{w09001800}, []string{w08002000}, false, false},
		{"requested touching principal end", []string{w09001800}, []string{w1830}, false, false},
		{"requested at principal edge", []string{w09001800}, []string{`varwof/constraint-v1:time:window:[{"start":"17:30","end":"18:00"}]`}, true, false},
		{
			"cross-midnight principal covers tail segment",
			[]string{wMidnight}, []string{wMidnightIn}, true, false,
		},
		{
			"cross-midnight principal does not cover a midday segment",
			[]string{wMidnight}, []string{w1012}, false, false,
		},
		{"max_rows within", []string{"varwof/constraint-v1:max_rows:100"}, []string{"varwof/constraint-v1:max_rows:50"}, true, false},
		{"max_rows equal", []string{"varwof/constraint-v1:max_rows:100"}, []string{"varwof/constraint-v1:max_rows:100"}, true, false},
		{"max_rows exceeded", []string{"varwof/constraint-v1:max_rows:100"}, []string{"varwof/constraint-v1:max_rows:200"}, false, false},
		{
			"cidr contained",
			[]string{"varwof/constraint-v1:network:cidr:[\"10.0.0.0/8\"]"},
			[]string{"varwof/constraint-v1:network:cidr:[\"10.1.2.0/24\"]"},
			true, false,
		},
		{
			"cidr not contained",
			[]string{"varwof/constraint-v1:network:cidr:[\"10.0.0.0/8\"]"},
			[]string{"varwof/constraint-v1:network:cidr:[\"11.0.0.0/8\"]"},
			false, false,
		},
		{
			"v4 not inside v6",
			[]string{"varwof/constraint-v1:network:cidr:[\"::/0\"]"},
			[]string{"varwof/constraint-v1:network:cidr:[\"10.0.0.0/8\"]"},
			false, false,
		},
		{
			"requested type unbounded by principal",
			[]string{"varwof/constraint-v1:max_rows:10"},
			[]string{`varwof/constraint-v1:time:window:[{"start":"00:00","end":"06:00"}]`},
			false, false,
		},
		{"unknown requested type errors", []string{"varwof/constraint-v1:max_rows:10"}, []string{"payments/quota-v1:daily:1000000"}, false, true},
		{"malformed requested errors", []string{"varwof/constraint-v1:max_rows:10"}, []string{"varwof/constraint-v1:time:window:3600"}, false, true},
		{"malformed principal errors", []string{"varwof/constraint-v1:time:window:3600"}, []string{"varwof/constraint-v1:max_rows:10"}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := SubsetConstraints(c.principal, c.requested)
			if c.wantErr {
				if err == nil {
					t.Fatalf("SubsetConstraints = (%v, nil), want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SubsetConstraints returned unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("SubsetConstraints = %v, want %v", got, c.want)
			}
		})
	}
}

// The wire capability → string → subset path used by both the DA signer and
// the CA reconstruction must agree on the very same strings.
func TestConstraintStringRoundTrip(t *testing.T) {
	cap := pki.Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "time:window", Parameters: []byte(`[{"start":"09:00","end":"18:00"}]`)}
	s, err := ConstraintString(cap)
	if err != nil {
		t.Fatal(err)
	}
	if s != w09001800 {
		t.Fatalf("round trip string = %q, want %q", s, w09001800)
	}
	if err := ValidateConstraint(s); err != nil {
		t.Fatal(err)
	}
}

func TestSubsetConstraintsUnboundedPrincipalAcceptsAny(t *testing.T) {
	ok, err := SubsetConstraints(nil, []string{w09001800, "varwof/constraint-v1:max_rows:5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("empty principal must not bound any request")
	}
}

func TestSubsetConstraintsErrorsMentionConstraint(t *testing.T) {
	_, err := SubsetConstraints([]string{"varwof/constraint-v1:max_rows:10"}, []string{"weird/constraint-v1:x:1"})
	if err == nil || !strings.Contains(err.Error(), "unknown_constraint") {
		t.Fatalf("want unknown_constraint error, got %v", err)
	}
}
