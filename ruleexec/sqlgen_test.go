// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestGenerateSelectSQL(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		t.Fatalf("generate sql: %v", err)
	}
	want := "SELECT `id`, `name` FROM `customers` WHERE (BINARY `tenant_id` = ?) LIMIT 100"
	if sql != want {
		t.Fatalf("sql mismatch:\n got: %s\nwant: %s", sql, want)
	}
	if !reflect.DeepEqual(args, []any{"org-a"}) {
		t.Fatalf("args mismatch: %v", args)
	}
}

func TestGenerateSelectSQLVariants(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		want     string
		wantArgs []any
	}{
		{
			name: "star columns no filter",
			raw:  `{"tables":["logs"],"columns":{"logs":"*"},"limit":{"max":10}}`,
			want: "SELECT * FROM `logs` LIMIT 10",
		},
		{
			name: "in + between",
			raw: `{"tables":["orders"],"columns":{"orders":["id","amount"]},
				"row_filter":{"orders":{"and":[
					{"column":"status","op":"in","value":["open","paid"]},
					{"column":"amount","op":"between","value":[1,1000]},
					{"column":"note","op":"=","value":"it's"}
				]}},
				"limit":{"max":5}}`,
			want:     "SELECT `id`, `amount` FROM `orders` WHERE (BINARY `status` IN (?, ?)) AND (`amount` BETWEEN ? AND ?) AND (BINARY `note` = ?) LIMIT 5",
			wantArgs: []any{"open", "paid", float64(1), float64(1000), "it's"},
		},
		{
			name: "or + not",
			raw: `{"tables":["events"],"columns":{"events":["id"]},
				"row_filter":{"events":{"or":[
					{"column":"kind","op":"=","value":"a"},
					{"not":{"column":"kind","op":"=","value":"b"}}
				]}}}`,
			want:     "SELECT `id` FROM `events` WHERE (BINARY `kind` = ?) OR (NOT (BINARY `kind` = ?))",
			wantArgs: []any{"a", "b"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql, args, err := GenerateSelectSQL(json.RawMessage(c.raw))
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if sql != c.want {
				t.Fatalf("sql mismatch:\n got: %s\nwant: %s", sql, c.want)
			}
			if len(args) == 0 && len(c.wantArgs) == 0 {
				return
			}
			if !reflect.DeepEqual(args, c.wantArgs) {
				t.Fatalf("args mismatch:\n got: %v\nwant: %v", args, c.wantArgs)
			}
		})
	}
}

func TestGenerateSelectSQLErrors(t *testing.T) {
	// two tables -> v1 rejects
	if _, _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a","b"],"columns":{"a":["id"]}}`)); err == nil {
		t.Fatalf("two tables must fail in v1")
	}
	// unsupported filter op
	if _, _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"regexp","value":"x"}}}`)); err == nil {
		t.Fatalf("unsupported op must fail")
	}
	// SQL injection attempt must land in args, never in the statement text
	raw := `{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"=","value":"1 OR 1=1"}}}`
	sql, args, err := GenerateSelectSQL(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if sql != "SELECT `id` FROM `a` WHERE BINARY `id` = ?" {
		t.Fatalf("unexpected sql: %s", sql)
	}
	if strings.Contains(sql, "1 OR 1=1") {
		t.Fatalf("value must not appear in the statement: %s", sql)
	}
	if !reflect.DeepEqual(args, []any{"1 OR 1=1"}) {
		t.Fatalf("args mismatch: %v", args)
	}
}

func TestSQLNullHandling(t *testing.T) {
	// comparing to NULL is rejected: use "is null" / "is not null"
	if _, _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"=","value":null}}}`)); err == nil {
		t.Fatalf("comparison with NULL must be rejected")
	}
	// null inside IN list is rejected
	if _, _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"in","value":["x",null]}}}`)); err == nil {
		t.Fatalf("null in IN list must be rejected")
	}
	// between with null bound is rejected
	if _, _, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"between","value":[null,5]}}}`)); err == nil {
		t.Fatalf("null between bound must be rejected")
	}
	// is null / is not null remain the supported NULL tests (no args)
	sql, args, err := GenerateSelectSQL(json.RawMessage(`{"tables":["a"],"columns":{"a":["id"]},
		"row_filter":{"a":{"column":"id","op":"is null"}}}`))
	if err != nil || sql != "SELECT `id` FROM `a` WHERE `id` IS NULL" || len(args) != 0 {
		t.Fatalf("is null mapping: %s args=%v err=%v", sql, args, err)
	}
}
