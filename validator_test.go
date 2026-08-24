// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"testing"
)

func TestValidateCapabilitiesValid(t *testing.T) {
	r := NewRegistry()
	r.Register(testDef("varwof/core", "cert:issue", "cert:revoke", "crl:read"))

	result := r.ValidateCapabilities([]string{
		"varwof/core:cert:issue",
		"varwof/core:cert:revoke",
	})
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
	if result.Checked != 2 {
		t.Errorf("Checked = %d, want 2", result.Checked)
	}
}

func TestValidateCapabilitiesErrors(t *testing.T) {
	r := NewRegistry()
	r.Register(testDef("varwof/core", "cert:issue"))

	result := r.ValidateCapabilities([]string{
		"varwof/core:cert:issue",
		"bad-format",
		"no/scheme:cap",
		"varwof/core:nonexistent",
	})
	if result.Valid {
		t.Error("expected invalid")
	}
	if len(result.Errors) != 3 {
		t.Errorf("Errors = %d, want 3", len(result.Errors))
	}
	if result.Checked != 4 {
		t.Errorf("Checked = %d, want 4", result.Checked)
	}
}

func TestValidateCapabilitiesEmpty(t *testing.T) {
	r := NewRegistry()
	result := r.ValidateCapabilities(nil)
	if !result.Valid {
		t.Error("empty list should be valid")
	}
	if result.Checked != 0 {
		t.Errorf("Checked = %d, want 0", result.Checked)
	}
}

func TestCheckSubset(t *testing.T) {
	r := NewRegistry()

	allowed := []string{"varwof/core:cert:issue", "varwof/core:cert:revoke"}
	declared := []string{"varwof/core:cert:issue"}
	denied := r.CheckSubset(declared, allowed)
	if len(denied) != 0 {
		t.Errorf("unexpected denied: %v", denied)
	}

	declared2 := []string{"varwof/core:cert:issue", "oracle/mysql:query:users"}
	denied2 := r.CheckSubset(declared2, allowed)
	if len(denied2) != 1 || denied2[0] != "oracle/mysql:query:users" {
		t.Errorf("expected [oracle/mysql:query:users], got %v", denied2)
	}

	// case insensitive
	denied3 := r.CheckSubset([]string{"VARWOF/CORE:CERT:ISSUE"}, allowed)
	if len(denied3) != 0 {
		t.Errorf("case insensitive check failed: denied = %v", denied3)
	}
}

func TestCheckIntersection(t *testing.T) {
	r := NewRegistry()

	setA := []string{"a:x", "b:y", "c:z"}
	setB := []string{"b:y", "d:w", "c:z"}
	common := r.CheckIntersection(setA, setB)
	if len(common) != 2 {
		t.Errorf("intersection = %v, want 2 items", common)
	}

	// empty intersection
	setC := []string{"a:x"}
	setD := []string{"b:y"}
	common2 := r.CheckIntersection(setC, setD)
	if len(common2) != 0 {
		t.Errorf("empty intersection expected, got %v", common2)
	}

	// case insensitive
	common3 := r.CheckIntersection([]string{"A:X"}, []string{"a:x"})
	if len(common3) != 1 {
		t.Errorf("case insensitive intersection failed: %v", common3)
	}
}

func TestFilterByScheme(t *testing.T) {
	caps := []string{
		"varwof/core:cert:issue",
		"varwof/core:crl:read",
		"oracle/mysql:query:users",
		"varwof/core:cert:revoke",
	}

	filtered := FilterByScheme(caps, "varwof/core")
	if len(filtered) != 3 {
		t.Errorf("FilterByScheme returned %d, want 3", len(filtered))
	}

	// no matches
	empty := FilterByScheme(caps, "no/scheme")
	if len(empty) != 0 {
		t.Errorf("FilterByScheme no match: got %d items", len(empty))
	}
}

func TestDeduplicate(t *testing.T) {
	input := []string{
		"varwof/core:cert:issue",
		"VARWOF/CORE:CERT:ISSUE",
		"oracle/mysql:query",
		"varwof/core:cert:issue",
	}
	result := Deduplicate(input)
	if len(result) != 2 {
		t.Errorf("Deduplicate returned %d items, want 2", len(result))
	}

	// empty
	empty := Deduplicate(nil)
	if len(empty) != 0 {
		t.Errorf("Deduplicate(nil) returned %d items", len(empty))
	}

	// no duplicates
	noDup := Deduplicate([]string{"a", "b", "c"})
	if len(noDup) != 3 {
		t.Errorf("Deduplicate no dups: got %d items", len(noDup))
	}
}

func TestValidationError(t *testing.T) {
	e := ValidationError{Field: "test", Message: "bad value"}
	if e.Error() != "test: bad value" {
		t.Errorf("ValidationError.Error() = %q, want %q", e.Error(), "test: bad value")
	}
}
