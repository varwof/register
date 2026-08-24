// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func writeSchemeFile(t *testing.T, dir, sub, schemeID, name, version string) {
	t.Helper()
	if sub != "" {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	jsonData := `{
		"scheme_id": "` + schemeID + `",
		"name": "` + name + `",
		"version": "` + version + `",
		"description": "test",
		"capabilities": [{"id": "do-thing", "description": "do a thing"}]
	}`
	path := filepath.Join(dir, sub, "v1.json")
	if err := os.WriteFile(path, []byte(jsonData), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEmbeddedRemoved(t *testing.T) {
	_, err := LoadEmbedded()
	if err == nil {
		t.Fatal("LoadEmbedded should return error after data split")
	}
}

func TestLoadFromFS(t *testing.T) {
	jsonData := `{
		"scheme_id": "test/product",
		"name": "Test Product",
		"version": "1.0.0",
		"description": "test",
		"capabilities": [{"id": "do-thing", "description": "do a thing"}]
	}`
	fsys := fstest.MapFS{
		"test/product/v1.json": {Data: []byte(jsonData)},
	}

	schemes, err := LoadFromFS(fsys)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}
	if len(schemes) != 1 {
		t.Fatalf("expected 1 scheme, got %d", len(schemes))
	}
	def, ok := schemes["test/product"]
	if !ok {
		t.Fatal("missing test/product scheme")
	}
	if def.Name != "Test Product" {
		t.Errorf("Name = %q", def.Name)
	}
}

func TestLoadFromFSSkipNonJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"readme.txt":      {Data: []byte("skip")},
		"valid/v1.json":   {Data: []byte(`{"scheme_id": "a/b", "name": "A", "capabilities": [{"id": "x"}]}`)},
		"other/readme.md": {Data: []byte("skip")},
		"x/v1.yaml":       {Data: []byte("skip")},
	}

	schemes, err := LoadFromFS(fsys)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}
	if len(schemes) != 1 {
		t.Errorf("expected 1 scheme (valid only), got %d", len(schemes))
	}
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()
	writeSchemeFile(t, dir, "", "t/a", "A", "1")
	writeSchemeFile(t, dir, "sub", "t/b", "B", "1")

	schemes, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	if len(schemes) != 2 {
		t.Errorf("expected 2 schemes, got %d", len(schemes))
	}
}

func TestLoadFromDirNotExist(t *testing.T) {
	_, err := LoadFromDir("/nonexistent/path/12345")
	if err == nil {
		t.Error("LoadFromDir nonexistent: expected error")
	}
}

func TestLoadFromBothEmptyDirError(t *testing.T) {
	_, err := LoadFromBoth("")
	if err == nil {
		t.Fatal("LoadFromBoth empty dir: expected error (embedded removed)")
	}
}

func TestLoadFromBothDiskOverride(t *testing.T) {
	dir := t.TempDir()
	overrideJSON := `{
		"scheme_id": "varwof/core",
		"name": "Override Core",
		"version": "99.0.0",
		"description": "disk override",
		"capabilities": [{"id": "overridden"}]
	}`
	os.WriteFile(filepath.Join(dir, "v1.json"), []byte(overrideJSON), 0644)

	schemes, err := LoadFromBoth(dir)
	if err != nil {
		t.Fatalf("LoadFromBoth with override: %v", err)
	}
	def := schemes["varwof/core"]
	if def == nil {
		t.Fatal("varwof/core not found")
	}
	if def.Version != "99.0.0" {
		t.Errorf("disk override not applied: Version = %q", def.Version)
	}
}

func TestNewRegistryWithEmbeddedRemoved(t *testing.T) {
	_, err := NewRegistryWithEmbedded()
	if err == nil {
		t.Fatal("NewRegistryWithEmbedded should return error after data split")
	}
}

func TestNewRegistryFromDisk(t *testing.T) {
	dir := t.TempDir()
	writeSchemeFile(t, dir, "varwof/core", "varwof/core", "Core", "1.0.0")
	writeSchemeFile(t, dir, "oracle/mysql", "oracle/mysql", "MySQL", "1.0.0")

	reg, err := NewRegistryFromDisk(dir)
	if err != nil {
		t.Fatalf("NewRegistryFromDisk: %v", err)
	}
	if !reg.Has("varwof/core") {
		t.Error("missing varwof/core")
	}
	if !reg.Has("oracle/mysql") {
		t.Error("missing oracle/mysql")
	}
}

func TestLoadFromFSInvalidJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"bad/v1.json": {Data: []byte("{invalid json")},
	}
	_, err := LoadFromFS(fsys)
	if err == nil {
		t.Error("LoadFromFS invalid JSON: expected error")
	}
}

func TestLoadFromFSMissingSchemeID(t *testing.T) {
	fsys := fstest.MapFS{
		"nosid/v1.json": {Data: []byte(`{"name": "no sid", "capabilities": [{"id": "x"}]}`)},
	}
	_, err := LoadFromFS(fsys)
	if err == nil {
		t.Error("LoadFromFS missing scheme_id: expected error")
	}
}

func TestLoadFromFSInvalidSchemeID(t *testing.T) {
	fsys := fstest.MapFS{
		"badid/v1.json": {Data: []byte(`{"scheme_id": "UPPER/BAD", "capabilities": [{"id": "x"}]}`)},
	}
	_, err := LoadFromFS(fsys)
	if err == nil {
		t.Error("LoadFromFS invalid scheme_id: expected error")
	}
}

func TestLoadFromFSNestedPaths(t *testing.T) {
	fsys := fstest.MapFS{
		"a/b/c/v1.json": {Data: []byte(`{"scheme_id": "x/y", "name": "X", "capabilities": [{"id": "z"}]}`)},
	}
	schemes, err := LoadFromFS(fsys)
	if err != nil {
		t.Fatalf("LoadFromFS nested: %v", err)
	}
	if schemes["x/y"] == nil {
		t.Error("LoadFromFS nested path: missing x/y")
	}
}
