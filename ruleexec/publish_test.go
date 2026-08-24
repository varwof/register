package ruleexec

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/register"
)

func TestPublishRules(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	schemeDir := filepath.Join(rulesDir, "std/database-v1")
	if err := os.MkdirAll(schemeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// v1.0: original demo rule (limit 100)
	v10 := ruleJSON
	// v1.1: higher minor, tighter limit (limit 50)
	v11 := strings.Replace(ruleJSON, `"limit": { "max": 100 }`, `"limit": { "max": 50 }`, 1)
	if v11 == v10 {
		t.Fatalf("v1.1 must differ from v1.0")
	}
	if err := os.WriteFile(filepath.Join(schemeDir, "v1.0.json"), []byte(v10), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(schemeDir, "v1.1.json"), []byte(v11), 0o644); err != nil {
		t.Fatal(err)
	}

	certPath, keyPath, cert, err := GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	manifest, err := PublishRules(rulesDir, outDir, certPath, keyPath)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	sp, ok := manifest.Schemes["std/database-v1"]
	if !ok {
		t.Fatalf("scheme missing from manifest: %+v", manifest)
	}
	if sp.Latest != "v1.1.json" {
		t.Fatalf("latest should be v1.1.json, got %q", sp.Latest)
	}

	// default.json must be byte-identical to the highest minor version.
	defBytes, err := os.ReadFile(filepath.Join(outDir, "std/database-v1", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(defBytes) != v11 {
		t.Fatalf("default.json must be a byte copy of v1.1")
	}

	// every published file (including default.json) verifies.
	for _, name := range append(append([]string{}, sp.Files...), "default.json") {
		rulePath := filepath.Join(outDir, "std/database-v1", name)
		if err := register.VerifyCapabilityPKCS7(rulePath, []*x509.Certificate{cert}); err != nil {
			t.Fatalf("signature of %s: %v", name, err)
		}
	}

	// invalid rule must fail the whole publish.
	bad := filepath.Join(schemeDir, "v1.2.json")
	if err := os.WriteFile(bad, []byte(`{"rule_id":"bad"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishRules(rulesDir, outDir, certPath, keyPath); err == nil {
		t.Fatalf("invalid rule must fail publish")
	}
}
