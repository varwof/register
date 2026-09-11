// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateSelectSQL renders the MySQL SQL for a database-v1 query:SELECT rule
// (v1 contract: exactly one table).  The params must already have passed
// Validate (rule.go); this function is the "translator" that turns the
// structured contract into a PARAMETERIZED statement.
//
// All values are returned as placeholders (?) plus args, in statement order:
// no value is ever spliced into SQL text.  Identifiers (table/column names)
// are still quoted with backticks, and are validated against the rule's
// declared tables/columns before rendering.
func GenerateSelectSQL(raw json.RawMessage) (string, []any, error) {
	var p struct {
		Tables    []string       `json:"tables"`
		Columns   map[string]any `json:"columns"`
		RowFilter map[string]any `json:"row_filter"`
		Limit     *struct {
			Max int `json:"max"`
		} `json:"limit"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", nil, fmt.Errorf("params: %w", err)
	}
	if len(p.Tables) != 1 {
		return "", nil, fmt.Errorf("v1 SELECT requires exactly one table")
	}
	tbl := p.Tables[0]

	cols, err := sqlColumnList(p.Columns[tbl], tbl)
	if err != nil {
		return "", nil, err
	}

	var where string
	var args []any
	if filt, ok := p.RowFilter[tbl]; ok {
		s, a, err := filterToSQL(filt)
		if err != nil {
			return "", nil, err
		}
		where = " WHERE " + s
		args = a
	}

	var limit string
	if p.Limit != nil && p.Limit.Max > 0 {
		limit = fmt.Sprintf(" LIMIT %d", p.Limit.Max)
	}
	return fmt.Sprintf("SELECT %s FROM %s%s%s", cols, quoteIdent(tbl), where, limit), args, nil
}

func sqlColumnList(v any, tbl string) (string, error) {
	switch cv := v.(type) {
	case string:
		if cv == "*" {
			return "*", nil
		}
		return "", fmt.Errorf("columns[%q] must be an array or \"*\"", tbl)
	case []any:
		if len(cv) == 0 {
			return "", fmt.Errorf("columns[%q] must not be empty", tbl)
		}
		var out []string
		for _, c := range cv {
			cs, ok := c.(string)
			if !ok {
				return "", fmt.Errorf("columns[%q] must be strings", tbl)
			}
			out = append(out, quoteIdent(cs))
		}
		return strings.Join(out, ", "), nil
	}
	return "", fmt.Errorf("columns[%q] must be an array or \"*\"", tbl)
}

// filterToSQL renders the structured filter AST as a MySQL WHERE
// expression. Only structured predicates are accepted (no raw SQL).
func filterToSQL(node any) (string, []any, error) {
	m, ok := node.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("filter must be an object")
	}
	if col, ok := m["column"].(string); ok {
		op, _ := m["op"].(string)
		return renderCondition(col, op, m["value"])
	}
	if and, ok := m["and"].([]any); ok {
		return renderList(" AND ", and)
	}
	if or, ok := m["or"].([]any); ok {
		return renderList(" OR ", or)
	}
	if inner, ok := m["not"]; ok {
		s, a, err := filterToSQL(inner)
		if err != nil {
			return "", nil, err
		}
		return "NOT (" + s + ")", a, nil
	}
	return "", nil, fmt.Errorf("invalid filter structure")
}

func renderList(join string, items []any) (string, []any, error) {
	if len(items) == 0 {
		return "", nil, fmt.Errorf("filter list must not be empty")
	}
	parts := make([]string, 0, len(items))
	var args []any
	for _, it := range items {
		s, a, err := filterToSQL(it)
		if err != nil {
			return "", nil, err
		}
		parts = append(parts, "("+s+")")
		args = append(args, a...)
	}
	return strings.Join(parts, join), args, nil
}

// sqlOp maps the structured filter op to its SQL keyword form.
var sqlOp = map[string]string{
	"=":           "=",
	"!=":          "!=",
	"<":           "<",
	"<=":          "<=",
	">":           ">",
	">=":          ">=",
	"in":          "IN",
	"not in":      "NOT IN",
	"between":     "BETWEEN",
	"like":        "LIKE",
	"is null":     "IS NULL",
	"is not null": "IS NOT NULL",
}

func renderCondition(col, op string, val any) (string, []any, error) {
	kw, ok := sqlOp[op]
	if !ok {
		return "", nil, fmt.Errorf("unsupported filter op %q", op)
	}
	q := colExpr(col, val)
	switch op {
	case "=", "!=", "<", "<=", ">", ">=":
		if val == nil {
			return "", nil, fmt.Errorf("op %s: comparing to NULL is not supported; use \"is null\" / \"is not null\"", op)
		}
		return q + " " + kw + " ?", []any{val}, nil
	case "in", "not in":
		list, ok := val.([]any)
		if !ok || len(list) == 0 {
			return "", nil, fmt.Errorf("op %s requires a non-empty list", op)
		}
		placeholders := make([]string, 0, len(list))
		args := make([]any, 0, len(list))
		for _, item := range list {
			if item == nil {
				return "", nil, fmt.Errorf("op %s: null elements are not allowed; use \"is null\" per column", op)
			}
			placeholders = append(placeholders, "?")
			args = append(args, item)
		}
		return q + " " + kw + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	case "between":
		list, ok := val.([]any)
		if !ok || len(list) != 2 {
			return "", nil, fmt.Errorf("op between requires [lo, hi]")
		}
		if list[0] == nil || list[1] == nil {
			return "", nil, fmt.Errorf("op between: null bounds are not allowed")
		}
		return q + " " + kw + " ? AND ?", []any{list[0], list[1]}, nil
	case "like":
		if val == nil {
			return "", nil, fmt.Errorf("op like: comparing to NULL is not supported")
		}
		return q + " " + kw + " ?", []any{val}, nil
	case "is null", "is not null":
		return q + " " + kw, nil, nil
	}
	return "", nil, fmt.Errorf("unsupported filter op %q", op)
}

// colExpr renders a column reference used in a comparison.  String
// comparisons are made case-sensitive with BINARY so that SQL matches the
// in-memory condition semantics (which is byte-exact) even under MySQL's
// default case-insensitive collations.  NULL comparisons are rejected by
// the callers: use "is null" / "is not null".
func colExpr(col string, val any) string {
	q := quoteIdent(col)
	switch v := val.(type) {
	case string:
		return "BINARY " + q
	case []any:
		for _, it := range v {
			if _, ok := it.(string); ok {
				return "BINARY " + q
			}
		}
		return q
	default:
		return q
	}
}

// quoteIdent quotes a MySQL identifier with backticks.
func quoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}
