// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import "testing"

// TestFlatParamValueValidation verifies flat parameter values are validated
// against ParameterDef type/min/max/enum (P0-1), not just key presence.
func TestFlatParamValueValidation(t *testing.T) {
	reg := testRegistry(t)

	cases := []struct {
		name string
		cap  string
		par  map[string]any
		ok   bool
	}{
		{"valid int", "cert:issue", map[string]any{"max_validity_days": 90}, true},
		{"below min", "cert:issue", map[string]any{"max_validity_days": 0}, false},
		{"above max", "cert:issue", map[string]any{"max_validity_days": 99999}, false},
		{"wrong type", "cert:issue", map[string]any{"max_validity_days": "abc"}, false},
		{"valid list", "cert:issue", map[string]any{"ca_scope": []any{"TLS CA", "HR CA"}}, true},
		{"list wrong elem", "cert:issue", map[string]any{"ca_scope": []any{123}}, false},
		{"unknown key", "cert:issue", map[string]any{"nope": 1}, false},
	}
	for _, c := range cases {
		results := reg.ValidateClaims([]CapabilityClaim{
			{SchemeID: "varwof/core", Capability: c.cap, Parameters: c.par},
		})
		got := len(results) == 1 && results[0].Valid
		if got != c.ok {
			t.Errorf("%s: valid=%v want %v (err=%v)", c.name, got, c.ok,
				func() string {
					if len(results) == 1 {
						return results[0].Error
					}
					return ""
				}())
		}
	}
}

// TestRequiredParamMissing verifies a capability-declared required parameter
// cannot be omitted from the claim.
func TestRequiredParamMissing(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&SchemeDefinition{
		SchemeID: "x/acme", Name: "acme", Version: "1.0.0",
		Vendor: "x", Product: "acme",
		Capabilities: []CapabilityEntry{{
			ID: "order:approve",
			Parameters: map[string]ParameterDef{
				"threshold": {Type: "int", Min: 1.0, Required: true},
			},
		}},
	})
	res := reg.ValidateClaims([]CapabilityClaim{
		{SchemeID: "x/acme", Capability: "order:approve", Parameters: map[string]any{}},
	})
	if len(res) != 1 || res[0].Valid {
		t.Fatalf("required param omission must be rejected: %+v", res)
	}
}

// TestSchemeVersionMismatch verifies a claim pinning a scheme version that
// does not match the loaded registry is rejected (P1-4).
func TestSchemeVersionMismatch(t *testing.T) {
	reg := testRegistry(t)
	res := reg.ValidateClaims([]CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "ca:list", SchemeVersion: "9.9.9"},
	})
	if len(res) != 1 || res[0].Valid {
		t.Fatalf("version mismatch must be rejected: %+v", res)
	}
	// Matching version passes.
	res = reg.ValidateClaims([]CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "ca:list", SchemeVersion: "1.0.0"},
	})
	if len(res) != 1 || !res[0].Valid {
		t.Fatalf("matching version must pass: %+v", res)
	}
}
