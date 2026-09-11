// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"os"
	"testing"
)

// TestConditionVectors runs the shared condition truth table
// (testdata/condition-vectors.json).  The same file is consumed by the
// TypeScript mirror (demo/rule-exec/ts/mini.test.ts), so the two
// implementations cannot drift on NULL / case / type semantics.
type condVector struct {
	ID         string         `json:"id"`
	Ctx        map[string]any `json:"ctx"`
	Condition  Condition      `json:"condition"`
	Derivation string         `json:"derivation"`
	Expect     struct {
		Result *bool `json:"result"`
		Error  bool  `json:"error"`
	} `json:"expect"`
}

func TestConditionVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/condition-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Cases []condVector `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no condition vectors")
	}
	for _, c := range file.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got, err := EvalCondition(c.Condition, c.Ctx, NewBudget(), 0)
			if c.Expect.Error {
				if err == nil {
					t.Fatalf("%s: expected an error, got result %v", c.Derivation, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", c.Derivation, err)
			}
			if c.Expect.Result == nil {
				t.Fatalf("%s: vector has neither result nor error", c.Derivation)
			}
			if got != *c.Expect.Result {
				t.Fatalf("%s: got %v want %v", c.Derivation, got, *c.Expect.Result)
			}
		})
	}
}
