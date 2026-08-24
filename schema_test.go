package register

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSchemeID(t *testing.T) {
	tests := []struct {
		input       string
		wantVendor  string
		wantProduct string
		wantOK      bool
	}{
		{"varwof/core", "varwof", "core", true},
		{"oracle/mysql", "oracle", "mysql", true},
		{"x-acme/order", "x-acme", "order", true},
		{"a/b", "a", "b", true},
		{"", "", "", false},
		{"no-slash", "", "", false},
		{"/no-vendor", "", "", false},
		{"no-product/", "", "", false},
		{"a/b/c", "a", "b/c", true},
		{"/", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			vendor, product, ok := ParseSchemeID(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseSchemeID(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok && (vendor != tt.wantVendor || product != tt.wantProduct) {
				t.Errorf("ParseSchemeID(%q) = (%q, %q), want (%q, %q)", tt.input, vendor, product, tt.wantVendor, tt.wantProduct)
			}
		})
	}
}

func TestFormatSchemeID(t *testing.T) {
	got := FormatSchemeID("varwof", "core")
	if got != "varwof/core" {
		t.Errorf("FormatSchemeID(\"varwof\",\"core\") = %q, want %q", got, "varwof/core")
	}
}

func TestValidateSchemeID(t *testing.T) {
	valid := []string{
		"varwof/core",
		"oracle/mysql",
		"x-acme/order",
		"a1/b2",
		"my-vendor/my-product",
	}
	for _, s := range valid {
		if err := ValidateSchemeID(s); err != nil {
			t.Errorf("ValidateSchemeID(%q) unexpected error: %v", s, err)
		}
	}

	invalid := []string{
		"",
		"no-slash",
		"/no-vendor",
		"no-product/",
		"UPPER/vendor",
		"varwof/UPPER",
		"varwof/core/extra",
		"va rb/oh",
		"varwof/core ",
	}
	for _, s := range invalid {
		if err := ValidateSchemeID(s); err == nil {
			t.Errorf("ValidateSchemeID(%q) expected error, got nil", s)
		}
	}
}

func TestParseCapability(t *testing.T) {
	tests := []struct {
		input      string
		wantScheme string
		wantCapID  string
		wantOK     bool
	}{
		{"varwof/core:cert:issue", "varwof/core", "cert:issue", true},
		{"oracle/mysql:query:users", "oracle/mysql", "query:users", true},
		{"varwof/core:simple", "varwof/core", "simple", true},
		{"no-slash:cap", "", "", false},
		{"no-colon", "", "", false},
		{"varwof/core:", "varwof/core", "", true},
		{"x/ac:a:b:c", "x/ac", "a:b:c", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			scheme, capID, ok := ParseCapability(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseCapability(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if ok {
				if scheme != tt.wantScheme {
					t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
				}
				if capID != tt.wantCapID {
					t.Errorf("capID = %q, want %q", capID, tt.wantCapID)
				}
			}
		})
	}
}

func TestFormatCapability(t *testing.T) {
	got := FormatCapability("varwof/core", "cert:issue")
	if got != "varwof/core:cert:issue" {
		t.Errorf("FormatCapability = %q, want %q", got, "varwof/core:cert:issue")
	}
}

func TestLoadScheme(t *testing.T) {
	dir := t.TempDir()

	goodJSON := `{
		"scheme_id": "test/abc",
		"name": "Test",
		"version": "1.0.0",
		"description": "test",
		"capabilities": [{"id": "cap1", "description": "cap1"}]
	}`
	if err := os.WriteFile(filepath.Join(dir, "v1.json"), []byte(goodJSON), 0644); err != nil {
		t.Fatal(err)
	}

	def, err := LoadScheme(filepath.Join(dir, "v1.json"))
	if err != nil {
		t.Fatalf("LoadScheme valid file: %v", err)
	}
	if def.SchemeID != "test/abc" {
		t.Errorf("SchemeID = %q, want test/abc", def.SchemeID)
	}
	if def.Vendor != "test" || def.Product != "abc" {
		t.Errorf("auto-filled vendor/product = %q/%q, want test/abc", def.Vendor, def.Product)
	}

	// missing scheme_id
	badJSON := `{"name": "bad"}`
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(badJSON), 0644)
	_, err = LoadScheme(filepath.Join(dir, "bad.json"))
	if err == nil {
		t.Error("LoadScheme missing scheme_id: expected error")
	}

	// invalid scheme_id
	badID := `{"scheme_id": "UPPER/BAD", "name": "bad", "capabilities": [{"id": "x"}]}`
	os.WriteFile(filepath.Join(dir, "bad2.json"), []byte(badID), 0644)
	_, err = LoadScheme(filepath.Join(dir, "bad2.json"))
	if err == nil {
		t.Error("LoadScheme invalid scheme_id: expected error")
	}

	// no capabilities
	noCaps := `{"scheme_id": "t/a", "name": "no caps", "capabilities": []}`
	os.WriteFile(filepath.Join(dir, "bad3.json"), []byte(noCaps), 0644)
	_, err = LoadScheme(filepath.Join(dir, "bad3.json"))
	if err == nil {
		t.Error("LoadScheme no capabilities: expected error")
	}

	// non-existent file
	_, err = LoadScheme(filepath.Join(dir, "nonexistent.json"))
	if err == nil {
		t.Error("LoadScheme nonexistent file: expected error")
	}

	// invalid JSON
	os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{bad json"), 0644)
	_, err = LoadScheme(filepath.Join(dir, "broken.json"))
	if err == nil {
		t.Error("LoadScheme broken JSON: expected error")
	}
}

func TestListCapabilities(t *testing.T) {
	def := &SchemeDefinition{
		Capabilities: []CapabilityEntry{
			{ID: "z-cap"},
			{ID: "a-cap"},
			{ID: "m-cap"},
		},
	}
	ids := ListCapabilities(def)
	if len(ids) != 3 {
		t.Fatalf("ListCapabilities returned %d items, want 3", len(ids))
	}
	if ids[0] != "a-cap" || ids[1] != "m-cap" || ids[2] != "z-cap" {
		t.Errorf("ListCapabilities not sorted: %v", ids)
	}
}

func TestLoadAllSchemes(t *testing.T) {
	dir := t.TempDir()

	json1 := `{"scheme_id": "v/a", "name": "A", "version": "1", "capabilities": [{"id": "c1"}]}`
	json2 := `{"scheme_id": "v/b", "name": "B", "version": "1", "capabilities": [{"id": "c2"}]}`
	os.WriteFile(filepath.Join(dir, "v1.json"), []byte(json1), 0644)
	os.WriteFile(filepath.Join(dir, "v2.json"), []byte(json2), 0644)
	// non-matching file should be skipped
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("skip"), 0644)
	os.WriteFile(filepath.Join(dir, "other.json"), []byte(`{"skip": true}`), 0644)

	schemes, err := LoadAllSchemes(dir)
	if err != nil {
		t.Fatalf("LoadAllSchemes: %v", err)
	}
	if len(schemes) != 2 {
		t.Errorf("LoadAllSchemes returned %d schemes, want 2", len(schemes))
	}
	if schemes["v/a"] == nil {
		t.Error("LoadAllSchemes missing scheme v/a")
	}
	if schemes["v/b"] == nil {
		t.Error("LoadAllSchemes missing scheme v/b")
	}
}
