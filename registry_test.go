// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"strings"
	"testing"
)

func testDef(id string, caps ...string) *SchemeDefinition {
	entries := make([]CapabilityEntry, len(caps))
	for i, c := range caps {
		entries[i] = CapabilityEntry{ID: c, Description: "desc-" + c}
	}
	vendor, product, _ := ParseSchemeID(id)
	return &SchemeDefinition{
		SchemeID:     id,
		Name:         "Test " + id,
		Version:      "1.0.0",
		Description:  "test scheme",
		Vendor:       vendor,
		Product:      product,
		Capabilities: entries,
	}
}

// mustRegister registers a scheme in tests, failing the test on the R18
// duplicate-scheme_id error.
func mustRegister(t *testing.T, r *Registry, id string, caps ...string) {
	t.Helper()
	if err := r.Register(testDef(id, caps...)); err != nil {
		t.Fatalf("Register(%q): %v", id, err)
	}
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if len(r.SchemeIDs()) != 0 {
		t.Errorf("empty registry has %d schemes, want 0", len(r.SchemeIDs()))
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	def := testDef("acme/widget", "read", "write")
	if err := r.Register(def); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Get("acme/widget")
	if !ok {
		t.Fatal("Get(acme/widget) returned false")
	}
	if got.Name != "Test acme/widget" {
		t.Errorf("Name = %q, want %q", got.Name, "Test acme/widget")
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true")
	}
}

func TestHas(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, "a/b")

	if !r.Has("a/b") {
		t.Error("Has(a/b) = false, want true")
	}
	if r.Has("b/c") {
		t.Error("Has(b/c) = true, want false")
	}
}

func TestHasCapability(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, "a/b", "cap1", "cap2")

	if !r.HasCapability("a/b", "cap1") {
		t.Error("HasCapability(a/b, cap1) = false")
	}
	if !r.HasCapability("a/b", "cap2") {
		t.Error("HasCapability(a/b, cap2) = false")
	}
	if r.HasCapability("a/b", "cap3") {
		t.Error("HasCapability(a/b, cap3) = true, want false")
	}
	if r.HasCapability("x/y", "cap1") {
		t.Error("HasCapability(x/y, cap1) = true, want false")
	}
}

func TestValidateCapability(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, "varwof/core-v1", "cert:issue", "cert:revoke")

	def, cap, err := r.ValidateCapability("varwof/core-v1:cert:issue")
	if err != nil {
		t.Fatalf("ValidateCapability valid: %v", err)
	}
	if def.SchemeID != "varwof/core-v1" {
		t.Errorf("scheme = %q", def.SchemeID)
	}
	if cap.ID != "cert:issue" {
		t.Errorf("cap ID = %q", cap.ID)
	}

	// invalid format
	_, _, err = r.ValidateCapability("bad-format")
	if err == nil {
		t.Error("ValidateCapability bad format: expected error")
	}

	// unknown scheme
	_, _, err = r.ValidateCapability("no/scheme:cap")
	if err == nil {
		t.Error("ValidateCapability unknown scheme: expected error")
	}

	// unknown capability
	_, _, err = r.ValidateCapability("varwof/core-v1:nonexistent")
	if err == nil {
		t.Error("ValidateCapability unknown cap: expected error")
	}
}

func TestSchemeIDs(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, "z/a")
	mustRegister(t, r, "a/b")
	mustRegister(t, r, "m/c")

	ids := r.SchemeIDs()
	if len(ids) != 3 {
		t.Fatalf("SchemeIDs returned %d, want 3", len(ids))
	}
	if ids[0] != "a/b" || ids[1] != "m/c" || ids[2] != "z/a" {
		t.Errorf("SchemeIDs not sorted: %v", ids)
	}
}

func TestSummary(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, "a/b", "x", "y")

	s := r.Summary()
	if !strings.Contains(s, "1 scheme(s)") {
		t.Errorf("Summary missing scheme count: %s", s)
	}
	if !strings.Contains(s, "2 capability(ies)") {
		t.Errorf("Summary missing capability count: %s", s)
	}
}

func TestRegisterDuplicateRejected(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testDef("a/b", "old-cap")); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(testDef("a/b", "new-cap")); err == nil {
		t.Fatal("duplicate Register returned nil error, want refusal (R18)")
	}

	def, ok := r.Get("a/b")
	if !ok {
		t.Fatal("Get failed after register")
	}
	if len(def.Capabilities) != 1 || def.Capabilities[0].ID != "old-cap" {
		t.Errorf("duplicate must not replace: caps = %v", def.Capabilities)
	}
}

func TestConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Register(testDef("a/b", "cap"))
		for i := 0; i < 100; i++ {
			r.Has("a/b")
			r.SchemeIDs()
		}
	}()
	for i := 0; i < 100; i++ {
		r.Has("a/b")
		r.SchemeIDs()
	}
	<-done
}
