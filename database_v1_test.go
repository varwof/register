// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"path/filepath"
	"testing"
)

// TestDatabaseV1Registered verifies the canonical std/database-v1
// scheme is loadable from the capability data tree, carries structured
// params_schema, and its capabilities validate.
func TestDatabaseV1Registered(t *testing.T) {
	reg, err := LoadFromDir(filepath.Join("testdata", "capability"))
	if err != nil {
		t.Fatal(err)
	}
	def, ok := reg["std/database-v1"]
	if !ok {
		t.Fatalf("std/database-v1 not found in capability data")
	}
	if len(def.Capabilities) < 7 {
		t.Fatalf("expected >=7 capabilities, got %d", len(def.Capabilities))
	}
	var selectCap *CapabilityEntry
	for i := range def.Capabilities {
		if def.Capabilities[i].ID == "query:SELECT" {
			selectCap = &def.Capabilities[i]
		}
	}
	if selectCap == nil {
		t.Fatalf("query:SELECT capability missing")
	}
	if len(selectCap.ParamsSchema) == 0 {
		t.Fatalf("query:SELECT must carry params_schema")
	}

	r := NewRegistry()
	if err := r.Register(def); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, id := range []string{"std/database-v1:query:SELECT", "std/database-v1:query:INSERT", "std/database-v1:admin:TRUNCATE"} {
		if _, _, err := r.ValidateCapability(id); err != nil {
			t.Fatalf("registered capability %s must validate: %v", id, err)
		}
	}
	if _, _, err := r.ValidateCapability("std/database-v1:query:EXPLAIN"); err == nil {
		t.Fatalf("unregistered capability must fail")
	}
}

// R-5: negative cases for a structured scheme, through the same validation
// entry point an operation uses.
func TestDatabaseV1NegativeParams(t *testing.T) {
	reg, err := LoadFromDir(filepath.Join("testdata", "capability"))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := reg["std/database-v1"]
	if !ok {
		t.Fatal("std/database-v1 not found")
	}
	var selectCap *CapabilityEntry
	for i := range r.Capabilities {
		if r.Capabilities[i].ID == "query:SELECT" {
			selectCap = &r.Capabilities[i]
			break
		}
	}
	if selectCap == nil {
		t.Fatal("query:SELECT not found")
	}
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"tables not an array", map[string]any{"tables": "orders"}},
		{"unknown parameter", map[string]any{"tables": []any{"orders"}, "nope": 1.0}},
		{"limit wrong type", map[string]any{"tables": []any{"orders"}, "limit": "10"}},
	}
	for _, c := range cases {
		if err := validateParamsSchema(selectCap.ParamsSchema, c.params); err == nil {
			t.Errorf("%s: want a refusal", c.name)
		}
	}
}
