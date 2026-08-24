// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"strings"
	"testing"
)

// 构建测试用的 scheme 注册表。
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	reg.Register(&SchemeDefinition{
		SchemeID: "varwof/core",
		Name:     "core",
		Version:  "1.0.0",
		Vendor:   "varwof",
		Product:  "core",
		Capabilities: []CapabilityEntry{
			{ID: "ca:list", Description: "列出 CA"},
			{ID: "ca:info", Description: "CA 详情"},
			{ID: "cert:issue", Description: "签发",
				Summary:  "签发证书",
				Usage:    "为服务/设备签发证书时",
				WhenNot:  "纯查询任务不需要",
				Examples: []string{"签发 HTTPS 证书"},
				Parameters: map[string]ParameterDef{
					"max_validity_days": {Type: "int", Default: float64(365), Min: 1.0, Max: 3650.0},
					"ca_scope":          {Type: "list"},
				}},
			{ID: "cert:revoke", Description: "吊销"},
			{ID: "key:recover", Description: "密钥恢复"},
		},
	})
	return reg
}

func TestValidateClaimsValid(t *testing.T) {
	reg := testRegistry(t)
	claims := []CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "cert:issue", Parameters: map[string]any{"max_validity_days": 90}},
		{SchemeID: "varwof/core", Capability: "ca:list"},
	}
	results := reg.ValidateClaims(claims)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("claim %s:%s should be valid, err=%q", r.Claim.SchemeID, r.Claim.Capability, r.Error)
		}
	}
}

func TestValidateClaimsUnknownScheme(t *testing.T) {
	reg := testRegistry(t)
	results := reg.ValidateClaims([]CapabilityClaim{{SchemeID: "bogus/vendor", Capability: "foo:bar"}})
	if len(results) != 1 || results[0].Valid {
		t.Fatalf("expected invalid result, got %+v", results)
	}
	if !strings.Contains(results[0].Error, "unknown scheme") {
		t.Errorf("error = %q, want 'unknown scheme'", results[0].Error)
	}
}

func TestValidateClaimsUnknownCapability(t *testing.T) {
	reg := testRegistry(t)
	results := reg.ValidateClaims([]CapabilityClaim{{SchemeID: "varwof/core", Capability: "no:such"}})
	if len(results) != 1 || results[0].Valid {
		t.Fatalf("expected invalid result, got %+v", results)
	}
	if !strings.Contains(results[0].Error, "not in scheme") {
		t.Errorf("error = %q, want 'not in scheme'", results[0].Error)
	}
}

func TestValidateClaimsUnknownParam(t *testing.T) {
	reg := testRegistry(t)
	results := reg.ValidateClaims([]CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "cert:issue", Parameters: map[string]any{"nonexistent": true}},
	})
	if len(results) != 1 || results[0].Valid {
		t.Fatalf("expected invalid result, got %+v", results)
	}
	if !strings.Contains(results[0].Error, "unknown parameter") {
		t.Errorf("error = %q, want 'unknown parameter'", results[0].Error)
	}
}

func TestCheckMinimal_Redundant(t *testing.T) {
	reg := testRegistry(t)
	claims := []CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "ca:*"},
		{SchemeID: "varwof/core", Capability: "ca:list"}, // 被 ca:* 覆盖 → 冗余
	}
	rep := reg.CheckMinimalCapabilitySet(claims, nil)
	if len(rep.InvalidClaims) != 0 {
		t.Fatalf("unexpected invalid: %+v", rep.InvalidClaims)
	}
	if len(rep.RedundantClaims) != 1 {
		t.Fatalf("RedundantClaims = %d, want 1 (got %+v)", len(rep.RedundantClaims), rep.RedundantClaims)
	}
	if rep.RedundantClaims[0].Claim.Capability != "ca:list" {
		t.Errorf("redundant = %s, want ca:list", rep.RedundantClaims[0].Claim.Capability)
	}
	if rep.IsMinimal {
		t.Error("should not be minimal (redundant present)")
	}
}

func TestCheckMinimal_NoRedundant(t *testing.T) {
	reg := testRegistry(t)
	claims := []CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "ca:list"},
		{SchemeID: "varwof/core", Capability: "cert:issue"},
	}
	rep := reg.CheckMinimalCapabilitySet(claims, nil)
	if len(rep.InvalidClaims) != 0 || len(rep.RedundantClaims) != 0 {
		t.Fatalf("unexpected issues: invalid=%v redundant=%v", rep.InvalidClaims, rep.RedundantClaims)
	}
	if !rep.IsMinimal {
		t.Error("should be minimal")
	}
}

func TestCheckMinimal_MissingGranted(t *testing.T) {
	reg := testRegistry(t)
	claims := []CapabilityClaim{
		{SchemeID: "varwof/core", Capability: "cert:issue"},
		{SchemeID: "varwof/core", Capability: "key:recover"},
	}
	rep := reg.CheckMinimalCapabilitySet(claims, []string{"cert:issue", "ca:list"})
	if len(rep.MissingGranted) != 1 || rep.MissingGranted[0] != "varwof/core:key:recover" {
		t.Fatalf("MissingGranted = %v, want [varwof/core:key:recover]", rep.MissingGranted)
	}
	if rep.IsMinimal {
		t.Error("should not be minimal (missing granted)")
	}
}

func TestParseCapabilityClaims(t *testing.T) {
	data := []byte(`[
		{"scheme_id":"varwof/core","capability":"cert:issue","parameters":{"max_validity_days":90},"rationale":"x"},
		{"scheme_id":"varwof/gateway","capability":"proxy:http"}
	]`)
	claims, err := ParseCapabilityClaims(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("claims = %d, want 2", len(claims))
	}
	if claims[0].Capability != "cert:issue" || claims[1].SchemeID != "varwof/gateway" {
		t.Errorf("unexpected parse: %+v", claims)
	}
}

func TestParseCapabilityClaimsMissingField(t *testing.T) {
	data := []byte(`[{"scheme_id":"varwof/core"}]`)
	_, err := ParseCapabilityClaims(data)
	if err == nil {
		t.Fatal("expected error for missing capability field")
	}
}

func TestGenDocsContent(t *testing.T) {
	reg := testRegistry(t)
	def, _ := reg.Get("varwof/core")
	md, err := GenDocs(def)
	if err != nil {
		t.Fatalf("GenDocs: %v", err)
	}
	// 必须包含关键章节
	for _, want := range []string{
		"权限说明", "能力目录", "能力详细语义", "通配符与匹配规则", "最小权限生成指南",
		"`varwof/core:cert:issue`", "**何时需要**", "**何时不应授予**", "**示例**",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("GenDocs missing %q", want)
		}
	}
}
