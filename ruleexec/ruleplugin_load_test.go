package ruleexec

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	pki "github.com/varwof/types"
)

const gwRuleJSON = `{
	"rule_id": "gw-rule", "version": "1.0.0",
	"scheme": "std/database-v1", "capability": "query:SELECT",
	"params": {"tables": ["customers"], "columns": {"customers": ["id","name"]},
		"filter_columns": {"customers": ["tenant_id"]},
		"row_filter": {"customers": {"column": "tenant_id", "op": "=", "value": "org-a"}},
		"limit": {"max": 100}},
	"conditions": {"op": "and", "items": [
		{"op": "eq", "path": "request.method", "value": "GET"},
		{"op": "eq", "path": "request.query.tenant", "value": "org-a"}
	]}
}`

func TestRegisterRulePluginsFromDir(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "std/database-v1")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "v1.0.json"), []byte(gwRuleJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, cert, err := GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if _, err := PublishRules(filepath.Join(dir, "rules"), outDir, certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	reg := pki.NewPluginRegistry()
	schemes, err := RegisterRulePluginsFromDir(reg, outDir, []*x509.Certificate{cert}, nil)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(schemes) != 1 || schemes[0] != "std/database-v1" {
		t.Fatalf("schemes: %v", schemes)
	}
	if reg.Len() != 1 {
		t.Fatalf("expected 1 plugin, got %d", reg.Len())
	}

	// HTTP facts flow through the real registry -> plugin path.
	allow, err := reg.Execute("std/database-v1",
		&pki.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&pki.PluginContext{Method: "GET", Query: map[string][]string{"tenant": {"org-a"}}, Target: "query:SELECT"})
	if err != nil || allow.Decision != pki.PluginAllow {
		t.Fatalf("expected allow, got %+v err=%v", allow, err)
	}
	deny, err := reg.Execute("std/database-v1",
		&pki.Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"},
		&pki.PluginContext{Method: "POST", Query: map[string][]string{"tenant": {"org-a"}}, Target: "query:SELECT"})
	if err != nil || deny.Decision != pki.PluginDeny {
		t.Fatalf("expected deny for POST, got %+v err=%v", deny, err)
	}

	// Tampered rule must fail closed on a fresh registry.
	if err := os.WriteFile(filepath.Join(outDir, "std/database-v1", "default.json"),
		append([]byte(gwRuleJSON), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	reg2 := pki.NewPluginRegistry()
	if _, err := RegisterRulePluginsFromDir(reg2, outDir, []*x509.Certificate{cert}, nil); err == nil {
		t.Fatalf("tampered rule must fail registration")
	}
}
