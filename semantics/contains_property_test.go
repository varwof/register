// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestContainsProperty is the executable form of the CLC-D forward-closure
// property (draft-wei-clc-ext-00 §4/§7):
//
//	for every case (parent P, child C) and every operation o in the shared
//	ops sample:
//	  * Contains(P, C) MUST NOT raise, and
//	  * Contains(P, C) true AND Entails(C, o) true ==> Entails(P, o) true.
//
// The same case list also carries the explicit antisymmetry assertion
// (CL 13.10.8): Contains is antisymmetric on semantic equivalence classes —
// for every case, Contains(P, C) and Contains(C, P) both true is allowed only
// when P and C fall in the same semantic class (same identifier and
// semantically-equal params, with `params:{}` ≡ absent), never across two
// distinct classes (capability-language-core-v1 §13.3).
//
// The case list lives in the capability repository
// (data/_vectors/clc-d/containment-property-cases.json); override with
// CLC_D_PROPERTY_CASES.

type containPropertyCase struct {
	ID     string `json:"id"`
	Parent Grant  `json:"parent"`
	Child  Grant  `json:"child"`
}

type containPropertyFile struct {
	Ops   []Operation           `json:"ops"`
	Cases []containPropertyCase `json:"cases"`
}

func TestContainsProperty(t *testing.T) {
	path := os.Getenv("CLC_D_PROPERTY_CASES")
	if path == "" {
		path = filepath.Join("..", "..", "capability", "data", "_vectors", "clc-d", "containment-property-cases.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("property cases not found at %s (set CLC_D_PROPERTY_CASES): %v", path, err)
	}
	var file containPropertyFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(file.Cases) == 0 || len(file.Ops) == 0 {
		t.Fatalf("%s carries no cases or ops", path)
	}

	containedPairs := 0
	opChecks := 0
	antisymViolations := 0
	antisymMutual := 0
	for _, c := range file.Cases {
		res := Contains(c.Parent, c.Child)
		if res.Contains {
			containedPairs++
		}
		// Antisymmetry (§13.3): mutual containment must imply semantic
		// equivalence, so a distinct pair reporting both directions is a
		// contradiction (CL 13.10.8).
		if res.Contains && Contains(c.Child, c.Parent).Contains {
			antisymMutual++
			if semanticClass(c.Parent) != semanticClass(c.Child) {
				antisymViolations++
				t.Errorf("%s: Contains(P,C) and Contains(C,P) both true across distinct semantic classes "+
					"(parent=%+v child=%+v)", c.ID, c.Parent, c.Child)
			}
		}
		for _, op := range file.Ops {
			opChecks++
			if !Entails(c.Child, op).Entails {
				continue
			}
			if res.Contains && !Entails(c.Parent, op).Entails {
				t.Errorf("%s: Contains(P,C) true and Entails(C,op) true but Entails(P,op) false "+
					"(parent=%+v child=%+v op=%+v)", c.ID, c.Parent, c.Child, op)
			}
		}
	}
	t.Logf("property: %d cases, %d contained pairs, %d op-checks, "+
		"%d mutual-containment pairs, %d antisymmetry violations",
		len(file.Cases), containedPairs, opChecks, antisymMutual, antisymViolations)
}

// semanticClass returns a canonical fingerprint of a grant's semantic
// equivalence class: the identifier plus the canonical (RFC 8785) params,
// with an empty or absent params object collapsed to the same class (the
// §6.5/§13.3 rule that `params:{}` ≡ absent).  Two grants in the same class
// are indistinguable to Contains, so mutual containment between them is not an
// antisymmetry violation; mutual containment across two different classes is.
func semanticClass(g Grant) string {
	v := struct {
		ID     string         `json:"id"`
		Params map[string]any `json:"params,omitempty"`
	}{ID: g.ID}
	if len(g.Params) > 0 {
		v.Params = g.Params
	}
	b, err := CanonicalJSON(v)
	if err != nil {
		return g.ID
	}
	return string(b)
}
