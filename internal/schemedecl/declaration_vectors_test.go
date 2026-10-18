// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemedecl

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestDeclarationVectors runs the shared valid/invalid declaration corpus.
func TestDeclarationVectors(t *testing.T) {
	path := os.Getenv("CLC_SCHEME_DECLARATION_VECTORS")
	if path == "" {
		const def = "../../../capability/data/_vectors/clc-v1/scheme-declaration-vectors.json"
		if _, err := os.Stat(def); err == nil {
			path = def
		} else {
			path = "../capability/data/_vectors/clc-v1/scheme-declaration-vectors.json"
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("declaration corpus unavailable: %v", err)
	}
	var cases []struct {
		ID          string          `json:"id"`
		Expect      string          `json:"expect"`
		Code        string          `json:"code"`
		Declaration json.RawMessage `json:"declaration"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if len(cases) < 9 {
		t.Fatalf("corpus has %d cases, expected at least 9", len(cases))
	}
	for _, c := range cases {
		var d Declaration
		if err := json.Unmarshal(c.Declaration, &d); err != nil {
			t.Fatalf("%s: unmarshal: %v", c.ID, err)
		}
		err := d.Validate()
		switch c.Expect {
		case "accept":
			if err != nil {
				t.Errorf("%s: want accept, got %v", c.ID, err)
			}
		case "reject":
			if err == nil {
				t.Errorf("%s: want reject (%s), got accept", c.ID, c.Code)
			} else if c.Code != "" && !strings.Contains(err.Error(), c.Code) {
				t.Errorf("%s: want code %s, got %v", c.ID, c.Code, err)
			}
		default:
			t.Errorf("%s: unknown expectation %q", c.ID, c.Expect)
		}
	}
}
