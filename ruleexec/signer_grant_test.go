// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"os"
	"path/filepath"
	"testing"

	pki "github.com/varwof/types"

	"github.com/varwof/register"
	"github.com/varwof/register/internal/rulesigner"
)

// TestRuleWithinSignerGrant pins the publication boundary: a rule may only be
// published by a signer whose own AIC grant covers the rule's capability, and
// whose authorization constraints cover the rule's constraints.
func TestRuleWithinSignerGrant(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	ruleConstraint := []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: "allowed-cidr",
		Parameters: []byte(`["10.0.0.0/8"]`),
	}}

	cases := []struct {
		name        string
		caps        []pki.Capability
		constraints []pki.Capability
		wantOK      bool
		why         string
	}{
		{
			name:        "covering wildcard grant",
			caps:        []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}},
			constraints: ruleConstraint,
			wantOK:      true,
			why:         "签名者的 grant 覆盖规则能力（通配、无参数上界）且声明了规则约束",
		},
		{
			name:        "exact capability grant without params",
			caps:        []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}},
			constraints: ruleConstraint,
			wantOK:      true,
			why:         "未声明参数上界 = 不受限（CLC §6.3 step 3），规则参数在授权内",
		},
		{
			name:        "unrelated capability",
			caps:        []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "admin:*"}},
			constraints: ruleConstraint,
			wantOK:      false,
			why:         "签名者只被授权 admin，不能发布 query 规则",
		},
		{
			name: "bound too tight",
			caps: []pki.Capability{{
				SchemeId: "std/database-v1", CapabilityId: "query:*",
				Parameters: []byte(`{"limit":{"max":10}}`),
			}},
			constraints: ruleConstraint,
			wantOK:      false,
			why:         "签名者的 limit 上界（10）小于规则要求（100）",
		},
		{
			name:        "grant ok but constraint missing",
			caps:        []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}},
			constraints: nil,
			wantOK:      false,
			why:         "签名者未声明规则要求的 allowed-cidr 约束",
		},
		{
			name:        "no grant at all",
			caps:        nil,
			constraints: nil,
			wantOK:      false,
			why:         "签名证书没有 AIC 扩展（GenSignerCert 的默认形态）",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			_, _, cert, err := rulesigner.GenSignerCertWithGrant(dir, c.caps, c.constraints)
			if err != nil {
				t.Fatalf("gen signer: %v", err)
			}
			err = RuleWithinSignerGrant(rule, cert)
			if c.wantOK && err != nil {
				t.Fatalf("%s: expected authorization, got %v", c.why, err)
			}
			if !c.wantOK && err == nil {
				t.Fatalf("%s: expected rejection", c.why)
			}
		})
	}
}

// TestPluginLoadEnforcesSignerGrant is the end-to-end form: a rule signed by a
// signer whose grant does not cover it MUST fail registration, while the same
// rule loads under a covering grant.
func TestPluginLoadEnforcesSignerGrant(t *testing.T) {
	publishAndLoad := func(t *testing.T, caps, constraints []pki.Capability) error {
		t.Helper()
		dir := t.TempDir()
		certPath, keyPath, _, err := rulesigner.GenSignerCertWithGrant(dir, caps, constraints)
		if err != nil {
			t.Fatal(err)
		}
		rulePath := filepath.Join(dir, "rule.json")
		if err := os.WriteFile(rulePath, []byte(ruleJSON), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := register.SignCapability(certPath, keyPath, rulePath, rulePath+".p7s"); err != nil {
			t.Fatalf("sign: %v", err)
		}
		roots, err := register.LoadCertFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		_, err = LoadRulePlugin(rulePath, roots, demoHandler)
		return err
	}

	ruleConstraint := []pki.Capability{{
		SchemeId: "varwof/constraint-v1", CapabilityId: "allowed-cidr",
		Parameters: []byte(`["10.0.0.0/8"]`),
	}}

	if err := publishAndLoad(t, []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "admin:*"}}, ruleConstraint); err == nil {
		t.Fatalf("rule exceeding the signer's grant must not load")
	}
	if err := publishAndLoad(t, []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}}, ruleConstraint); err != nil {
		t.Fatalf("covering grant must load: %v", err)
	}
}
