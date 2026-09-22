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
	for _, c := range file.Cases {
		res := Contains(c.Parent, c.Child)
		if res.Entails {
			containedPairs++
		}
		for _, op := range file.Ops {
			opChecks++
			if !Entails(c.Child, op).Entails {
				continue
			}
			if res.Entails && !Entails(c.Parent, op).Entails {
				t.Errorf("%s: Contains(P,C) true and Entails(C,op) true but Entails(P,op) false "+
					"(parent=%+v child=%+v op=%+v)", c.ID, c.Parent, c.Child, op)
			}
		}
	}
	t.Logf("property: %d cases, %d contained pairs, %d op-checks",
		len(file.Cases), containedPairs, opChecks)
}
