// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRoles_Covered(t *testing.T) {
	r := NewRegistry()
	r.Register(&SchemeDefinition{
		SchemeID: "test/product",
		Name:     "Test",
		Capabilities: []CapabilityEntry{
			{ID: "cert:issue", Description: "issue certs"},
			{ID: "cert:list", Description: "list certs"},
		},
		Roles: map[string]RoleDef{
			"admin": {Grants: []string{"cert:issue", "cert:list"}},
		},
	})
	uncovered, err := r.ValidateRoles("test/product")
	if err != nil {
		t.Fatalf("ValidateRoles: %v", err)
	}
	if len(uncovered) != 0 {
		t.Errorf("expected no uncovered grants, got %v", uncovered)
	}
}

func TestValidateRoles_Uncovered(t *testing.T) {
	r := NewRegistry()
	r.Register(&SchemeDefinition{
		SchemeID: "test/product",
		Name:     "Test",
		Capabilities: []CapabilityEntry{
			{ID: "cert:issue"},
		},
		Roles: map[string]RoleDef{
			"admin": {Grants: []string{"cert:issue", "cert:delete"}},
		},
	})
	uncovered, err := r.ValidateRoles("test/product")
	if err != nil {
		t.Fatalf("ValidateRoles: %v", err)
	}
	if len(uncovered) != 1 || uncovered[0] != "admin:cert:delete" {
		t.Errorf("expected [admin:cert:delete], got %v", uncovered)
	}
}

func TestValidateRoles_UnknownScheme(t *testing.T) {
	r := NewRegistry()
	_, err := r.ValidateRoles("nonexistent/scheme")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestRoleGrantCovered(t *testing.T) {
	r := NewRegistry()
	r.Register(&SchemeDefinition{
		SchemeID: "test/product",
		Capabilities: []CapabilityEntry{
			{ID: "cert:issue"},
		},
	})
	if !r.RoleGrantCovered("test/product", "cert:issue") {
		t.Error("expected grant to be covered")
	}
	if r.RoleGrantCovered("test/product", "cert:delete") {
		t.Error("expected grant to NOT be covered")
	}
	if r.RoleGrantCovered("nonexistent/scheme", "cert:issue") {
		t.Error("expected false for unknown scheme")
	}
}

func TestMatchCapability_ExtraCases(t *testing.T) {
	tests := []struct {
		id      string
		pattern string
		want    bool
	}{
		{"ca:issue", "ca:*", true},
		{"ca:list", "ca:*", true},
		{"ca:issue", "db:*", false},
		{"any", "*", true},
		{"any", "**", true},
		{"x", "?", true},
		{"ab", "?", false},
		{"exact", "exact", true},
		{"nope", "exact", false},
	}
	for _, tt := range tests {
		got := MatchCapability(tt.id, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchCapability(%q, %q) = %v, want %v", tt.id, tt.pattern, got, tt.want)
		}
	}
}

func TestGenDocsToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.md")

	def := &SchemeDefinition{
		SchemeID:    "test/product",
		Name:        "Test Product",
		Version:     "1.0.0",
		Vendor:      "test",
		Product:     "product",
		Description: "A test product",
		Capabilities: []CapabilityEntry{
			{ID: "cert:issue", Description: "Issue certs", Summary: "Issue"},
		},
		Roles: map[string]RoleDef{
			"admin": {DisplayName: "Admin", Grants: []string{"cert:issue"}},
		},
	}

	if err := GenDocsToFile(def, outPath); err != nil {
		t.Fatalf("GenDocsToFile: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if len(content) == 0 {
		t.Fatal("empty output file")
	}
}

func TestGenDocsToFile_NilDef(t *testing.T) {
	err := GenDocsToFile(nil, "/tmp/nonexistent/output.md")
	if err == nil {
		t.Fatal("expected error for nil def")
	}
}

func TestGenDocs_NilDef(t *testing.T) {
	_, err := GenDocs(nil)
	if err == nil {
		t.Fatal("expected error for nil def")
	}
}
