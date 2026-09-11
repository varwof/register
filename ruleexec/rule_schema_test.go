// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestLoadRuleRejectsUnknownField is the regression guard for the silent-drop
// hazard: a misspelled field ("condtions") used to be ignored, so the rule
// loaded and executed without the constraint its author meant to write.
func TestLoadRuleRejectsUnknownField(t *testing.T) {
	base := `{"rule_id":"t","version":"1.0.0","scheme":"std/database-v1",
	          "capability":"query:SELECT","params":{"tables":["customers"]}}`
	if _, err := LoadRuleBytes([]byte(base)); err != nil {
		t.Fatalf("baseline rule must load: %v", err)
	}
	typo := `{"rule_id":"t","version":"1.0.0","scheme":"std/database-v1",
	          "capability":"query:SELECT","params":{"tables":["customers"]},
	          "condtions":{"op":"eq","path":"a","value":1}}`
	if _, err := LoadRuleBytes([]byte(typo)); err == nil {
		t.Fatal("misspelled field \"condtions\" must be rejected, not silently dropped")
	}
	stale := `{"rule_id":"t","version":"1.0.0","scheme":"std/database-v1",
	           "capability":"query:SELECT","params":{"tables":["customers"]},
	           "roles":["readonly"]}`
	if _, err := LoadRuleBytes([]byte(stale)); err == nil {
		t.Fatal("removed field \"roles\" must be rejected")
	}
}

// TestRuleSchemaMatchesStruct keeps the machine-readable rule schema
// (demo/rule-exec/rule.schema.json, the contract a generator targets) in step
// with the Go struct the loader enforces.  It is dependency-free: it compares
// the schema's declared property names with the struct's json tags, so the two
// cannot drift apart without failing here.
func TestRuleSchemaMatchesStruct(t *testing.T) {
	path := filepath.Join("..", "demo", "rule-exec", "rule.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("schema not found at %s: %v", path, err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	fromSchema := make([]string, 0, len(schema.Properties))
	for k := range schema.Properties {
		fromSchema = append(fromSchema, k)
	}
	sort.Strings(fromSchema)

	rt := reflect.TypeOf(Rule{})
	fromStruct := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				name = tag[:j]
				break
			}
		}
		fromStruct = append(fromStruct, name)
	}
	sort.Strings(fromStruct)

	if !reflect.DeepEqual(fromSchema, fromStruct) {
		t.Errorf("rule schema and ruleexec.Rule disagree\n  schema: %v\n  struct: %v", fromSchema, fromStruct)
	}

	// Every required field must exist in the struct.
	for _, req := range schema.Required {
		if !contains(fromStruct, req) {
			t.Errorf("schema requires %q, which the Rule struct does not declare", req)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
