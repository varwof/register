// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestSQLParityVectors pins the generated SQL to the values that
// demo/rule-exec/sql_parity.py executes on SQLite.  Together they check that
// the in-memory condition semantics and the SQL semantics agree
// (case-sensitive strings, IS NULL for null, IN / BETWEEN).
func TestSQLParityVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/sql-parity-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Cases []struct {
			ID         string          `json:"id"`
			Params     json.RawMessage `json:"params"`
			SQL        string          `json:"sql"`
			Args       []any           `json:"args"`
			Derivation string          `json:"derivation"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no sql parity vectors")
	}
	for _, c := range file.Cases {
		got, args, err := GenerateSelectSQL(c.Params)
		if err != nil {
			t.Fatalf("%s: generate: %v", c.ID, err)
		}
		if got != c.SQL {
			t.Fatalf("%s (%s):\n got: %s\nwant: %s", c.ID, c.Derivation, got, c.SQL)
		}
		if len(args) != len(c.Args) {
			t.Fatalf("%s: args %v, want %v", c.ID, args, c.Args)
		}
		for i := range args {
			// JSON numbers decode as float64; compare numerically.
			if fmt.Sprintf("%v", args[i]) != fmt.Sprintf("%v", c.Args[i]) {
				t.Fatalf("%s: arg[%d]=%v (%T), want %v (%T)", c.ID, i, args[i], args[i], c.Args[i], c.Args[i])
			}
		}
	}
}
