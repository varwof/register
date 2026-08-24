// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"testing"
)

func TestGenerateSelectSQL(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	got, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		t.Fatalf("generate sql: %v", err)
	}
	want := "SELECT `id`, `name` FROM `customers` WHERE (`tenant_id` = 'org-a') LIMIT 100"
	if got != want {
		t.Fatalf("sql mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestGenerateSelectSQLVariants(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "star columns no filter",
			raw:  `{"tables":["logs"],"columns":{"logs":"*"},"limit":{"max":10}}`,
			want: "SELECT * FROM `logs` LIMIT 10",
		},
		{
			name: "in + between + escaping",
			raw: `{"tables":["orders"],"columns":{"orders":["id","amount"]},
				"row_filter":{"orders":{"and":[
					{"column":"status","op":"in","value":["open","paid"]},
					{"column":"amount","op":"between","value":[1,1000]},
					{"column":"note","op":"=","value":"it's"}
				]}},
				"limit":{"max":5}}`,
			want: "SELECT `id`, `amount` FROM `orders` WHERE (`status` IN ('open', 'paid')) AND (`amount` BETWEEN 1 AND 1000) AND (`note` = 'it''s') LIMIT 5",
		},
		{
			name: "or + not",
			raw: `{"tables":["events"],"columns":{"events":["id"]},
				"row_filter":{"events":{"or":[
					{"column":"kind","op":"=","value":"a"},
					{"not":{"column":"kind","op":"=","value":"b"}}
				]}}}`,
			want: "SELECT `id` FROM `events` WHERE (`kind` = 'a') OR (NOT (`kind` = 'b'))",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := GenerateSelectSQL(json.RawMessage(c.raw))
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if got != c.want {
				t.Fatalf("sql mismatch:\n got: %s\nwant: %s", got, c.want)
			}
		})
	}
}

func TestGenerateSelectSQLErrors(t *testing.T) {
	// two tables -> v1 rejects
	if _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a","b"],"columns":{"a":["id"]}}`)); err == nil {
		t.Fatalf("two tables must fail in v1")
	}
	// unsupported filter op
	if _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"regexp","value":"x"}}}`)); err == nil {
		t.Fatalf("unsupported op must fail")
	}
	// raw SQL must not be accepted anywhere in the filter: the value is
	// escaped as a string literal, never spliced as code.
	raw := `{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"=","value":"1 OR 1=1"}}}`
	sql, err := GenerateSelectSQL(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT `id` FROM `a` WHERE `id` = '1 OR 1=1'"
	if sql != want {
		t.Fatalf("injection guard mismatch:\n got: %s\nwant: %s", sql, want)
	}
}
