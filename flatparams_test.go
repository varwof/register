// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"testing"
)

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
			{SchemeID: "varwof/core-v1", Capability: c.cap, Parameters: c.par},
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
	if err := reg.Register(&SchemeDefinition{
		SchemeID: "x/acme", Name: "acme", Version: "1.0.0",
		Vendor: "x", Product: "acme",
		Capabilities: []CapabilityEntry{{
			ID: "order:approve",
			Parameters: map[string]ParameterDef{
				"threshold": {Type: "int", Min: 1.0, Required: true},
			},
		}},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
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
		{SchemeID: "varwof/core-v1", Capability: "ca:list", SchemeVersion: "9.9.9"},
	})
	if len(res) != 1 || res[0].Valid {
		t.Fatalf("version mismatch must be rejected: %+v", res)
	}
	// Matching version passes.
	res = reg.ValidateClaims([]CapabilityClaim{
		{SchemeID: "varwof/core-v1", Capability: "ca:list", SchemeVersion: "1.0.0"},
	})
	if len(res) != 1 || !res[0].Valid {
		t.Fatalf("matching version must pass: %+v", res)
	}
}

// R-8: a refusal carries the offending path and a stable code, while the
// human message stays what it was.
func TestFlatParamStructuredError(t *testing.T) {
	err := validateFlatParamValue(ParameterDef{Type: "int"}, "max_validity_days", "seven")
	if err == nil {
		t.Fatal("want a refusal")
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error is not a *FieldError: %T", err)
	}
	if fe.Path != "max_validity_days" || fe.Code != "invalid_params_binding" {
		t.Fatalf("structured fields: got %q/%q", fe.Path, fe.Code)
	}
	if got, want := fe.Error(), `parameter "max_validity_days": must be an integer, got string`; got != want {
		t.Fatalf("message changed:\n got %s\nwant %s", got, want)
	}
}

// R-2 negative matrix: every refusal path of a flat parameter carries a stable
// code.
func TestFlatParamNegativeMatrix(t *testing.T) {
	cases := []struct {
		name string
		def  ParameterDef
		val  any
		code string
	}{
		{"int from string", ParameterDef{Type: "int"}, "7", "invalid_params_binding"},
		{"int below min", ParameterDef{Type: "int", Min: 3.0}, 2.0, "params_out_of_range"},
		{"int above max", ParameterDef{Type: "int", Max: 3.0}, 4.0, "params_out_of_range"},
		{"bool from int", ParameterDef{Type: "bool"}, 1.0, "invalid_params_binding"},
		{"string from int", ParameterDef{Type: "string"}, 1.0, "invalid_params_binding"},
		{"string not in enum", ParameterDef{Type: "string", Enum: []string{"a", "b"}}, "c", "not_in_enum"},
		{"list not array", ParameterDef{Type: "list"}, "a", "invalid_params_binding"},
		{"list element not string", ParameterDef{Type: "list"}, []any{1.0}, "invalid_params_binding"},
		{"list element not in enum", ParameterDef{Type: "list", Enum: []string{"a"}}, []any{"b"}, "not_in_enum"},
		{"unsupported type", ParameterDef{Type: "uuid"}, "x", "invalid_params_binding"},
	}
	for _, c := range cases {
		err := validateFlatParamValue(c.def, "p", c.val)
		var fe *FieldError
		if !errors.As(err, &fe) {
			t.Errorf("%s: got %v, want *FieldError", c.name, err)
			continue
		}
		if fe.Code != c.code || fe.Path != "p" {
			t.Errorf("%s: got %q/%q, want %q/p", c.name, fe.Path, fe.Code, c.code)
		}
	}
}
