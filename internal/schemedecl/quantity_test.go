// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemedecl

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

const (
	defaultDeclaration = "../../../capability/data/std/payments-v1/clc-declaration.json"
	defaultVectors     = "../../../capability/data/_vectors/clc-v1/quantity-vectors.json"
)

func declarationPath() string {
	if p := os.Getenv("CLC_SCHEME_DECLARATION"); p != "" {
		return p
	}
	if _, err := os.Stat(defaultDeclaration); err == nil {
		return defaultDeclaration
	}
	return "../capability/data/std/payments-v1/clc-declaration.json"
}

func vectorsPath() string {
	if p := os.Getenv("CLC_QUANTITY_VECTORS"); p != "" {
		return p
	}
	if _, err := os.Stat(defaultVectors); err == nil {
		return defaultVectors
	}
	return "../capability/data/_vectors/clc-v1/quantity-vectors.json"
}

// loadDeclarationOrSkip loads the sample declaration, or skips when the corpus
// repository is not checked out (the CI matrix does not clone capability; the
// dedicated clc-conformance workflow does).
func loadDeclarationOrSkip(t *testing.T) *Declaration {
	t.Helper()
	path := declarationPath()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("scheme declaration unavailable: %v", err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	return d
}

type vector struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	Capability string              `json:"capability"`
	Grants     []semantics.Grant   `json:"grants"`
	Operation  semantics.Operation `json:"operation"`
	Parent     semantics.Grant     `json:"parent"`
	Child      semantics.Grant     `json:"child"`
	Expect     struct {
		Verdict  string `json:"verdict"`
		Reason   string `json:"reason"`
		Contains bool   `json:"contains"`
	} `json:"expect"`
}

// TestQuantityVectors runs the quantity domain corpus against the sample
// declaration.
func TestQuantityVectors(t *testing.T) {
	d := loadDeclarationOrSkip(t)
	raw, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Skipf("quantity corpus unavailable: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if len(vs) < 8 {
		t.Fatalf("corpus has %d vectors, expected at least 8", len(vs))
	}
	for _, v := range vs {
		switch v.Kind {
		case "authorize":
			got := d.Authorize(v.Capability, v.Grants, v.Operation)
			if got.Verdict != v.Expect.Verdict ||
				(v.Expect.Reason != "" && !strings.HasPrefix(got.Reason, v.Expect.Reason)) {
				t.Errorf("%s: want %s/%s, got %s/%s", v.ID, v.Expect.Verdict, v.Expect.Reason, got.Verdict, got.Reason)
			}
		case "contains":
			ok, reason := d.Contains(v.Capability, v.Parent, v.Child)
			if ok != v.Expect.Contains ||
				(!ok && v.Expect.Reason != "" && !strings.HasPrefix(reason, v.Expect.Reason)) {
				t.Errorf("%s: want contains=%v/%s, got %v/%s", v.ID, v.Expect.Contains, v.Expect.Reason, ok, reason)
			}
		default:
			t.Errorf("%s: unknown kind %q", v.ID, v.Kind)
		}
	}
}

// TestDeclarationValidation pins the fail-closed declaration rules.
func TestDeclarationValidation(t *testing.T) {
	base := loadDeclarationOrSkip(t)

	bad := *base
	bad.Capabilities = map[string]Capability{
		"transfer": {Params: map[string]Param{"amount": {Domain: "money"}}},
	}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported_domain") {
		t.Errorf("unknown domain: want unsupported_domain, got %v", err)
	}

	bad2 := *base
	bad2.Digest = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := bad2.Validate(); err == nil || !strings.Contains(err.Error(), "digest_mismatch") {
		t.Errorf("digest mismatch: want declaration_digest_mismatch, got %v", err)
	}

	bad3 := *base
	bad3.Capabilities = map[string]Capability{
		"transfer": {Params: map[string]Param{"amount": {Domain: "quantity"}}},
	}
	if err := bad3.Validate(); err == nil || !strings.Contains(err.Error(), "quantity without unit") {
		t.Errorf("quantity without unit: got %v", err)
	}
}

// TestUnsupportedDomainRefused pins the fail-closed path: a domain the revision
// declares but this engine does not implement is refused at evaluation, not
// compared under the shape rule.
func TestUnsupportedDomainRefused(t *testing.T) {
	base := loadDeclarationOrSkip(t)
	decl := *base
	decl.Capabilities = map[string]Capability{
		"transfer": {Params: map[string]Param{"amount": {Domain: "money"}}},
	}
	got := decl.Authorize("transfer",
		[]semantics.Grant{{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 100}}},
		semantics.Operation{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 50}})
	if got.Verdict != semantics.VerdictDeny || got.Reason != "unsupported_domain" {
		t.Errorf("want deny/unsupported_domain, got %s/%s", got.Verdict, got.Reason)
	}
}

// TestStringDomains covers the three string-shaped declared domains.
func TestStringDomains(t *testing.T) {
	base := loadDeclarationOrSkip(t)
	raw, err := os.ReadFile(stringVectorsPath())
	if err != nil {
		t.Skipf("string-domain corpus unavailable: %v", err)
	}
	var cases []struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
		Param  string `json:"param"`
		Grant  any    `json:"grant"`
		Op     any    `json:"op"`
		Expect struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
		} `json:"expect"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("string-domain corpus: %v", err)
	}
	if len(cases) != 24 {
		t.Fatalf("string-domain corpus has %d cases, expected 24", len(cases))
	}
	for _, c := range cases {
		decl := *base
		decl.Capabilities = map[string]Capability{
			"transfer": {Params: map[string]Param{c.Param: {Domain: c.Domain}}},
		}
		got := decl.Authorize("transfer",
			[]semantics.Grant{{ID: "std/payments-v1:transfer", Params: map[string]any{c.Param: c.Grant}}},
			semantics.Operation{ID: "std/payments-v1:transfer", Params: map[string]any{c.Param: c.Op}})
		if got.Verdict != c.Expect.Verdict ||
			(c.Expect.Reason != "" && !strings.HasPrefix(got.Reason, c.Expect.Reason)) {
			t.Errorf("%s: want %s/%s, got %s/%s", c.ID, c.Expect.Verdict, c.Expect.Reason, got.Verdict, got.Reason)
		}
		// The same comparison must hold for containment.
		contained, _ := decl.Contains("transfer",
			semantics.Grant{ID: "std/payments-v1:transfer", Params: map[string]any{c.Param: c.Grant}},
			semantics.Grant{ID: "std/payments-v1:transfer", Params: map[string]any{c.Param: c.Op}})
		if contained != (c.Expect.Verdict == "allow") {
			t.Errorf("%s: containment want %v, got %v", c.ID, c.Expect.Verdict == "allow", contained)
		}
	}
}

func stringVectorsPath() string {
	if p := os.Getenv("CLC_STRING_DOMAIN_VECTORS"); p != "" {
		return p
	}
	const def = "../../../capability/data/_vectors/clc-v1/string-domain-vectors.json"
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return "../capability/data/_vectors/clc-v1/string-domain-vectors.json"
}

// TestDeclaredDomainRejectsParamBounds pins the §6.7 rule: a declared-domain
// parameter must live in params; a param_bounds entry on the same key is
// invalid_params_binding.
func TestDeclaredDomainRejectsParamBounds(t *testing.T) {
	base := loadDeclarationOrSkip(t)
	decl := *base
	g := semantics.Grant{
		ID:          "std/payments-v1:transfer",
		ParamBounds: map[string]any{"amount": map[string]any{"min": 1.0, "max": 10.0}},
	}
	op := semantics.Operation{ID: "std/payments-v1:transfer", Params: map[string]any{
		"amount": map[string]any{"value": 5.0, "unit": "CNY"},
	}}
	got := decl.Authorize("transfer", []semantics.Grant{g}, op)
	if got.Verdict != semantics.VerdictDeny || got.Reason != "invalid_params_binding" {
		t.Fatalf("want deny/invalid_params_binding, got %s/%s", got.Verdict, got.Reason)
	}
}
