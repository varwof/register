// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateSelectSQL renders the MySQL SQL for a database-v1
// query:SELECT rule (v1 contract: exactly one table). The params must
// already have passed Validate (rule.go); this function is the
// "translator" that turns the structured contract into SQL.
func GenerateSelectSQL(raw json.RawMessage) (string, error) {
	var p struct {
		Tables    []string       `json:"tables"`
		Columns   map[string]any `json:"columns"`
		RowFilter map[string]any `json:"row_filter"`
		Limit     *struct {
			Max int `json:"max"`
		} `json:"limit"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("params: %w", err)
	}
	if len(p.Tables) != 1 {
		return "", fmt.Errorf("v1 SELECT requires exactly one table")
	}
	tbl := p.Tables[0]

	cols, err := sqlColumnList(p.Columns[tbl], tbl)
	if err != nil {
		return "", err
	}

	var where string
	if filt, ok := p.RowFilter[tbl]; ok {
		s, err := filterToSQL(filt)
		if err != nil {
			return "", err
		}
		where = " WHERE " + s
	}

	var limit string
	if p.Limit != nil && p.Limit.Max > 0 {
		limit = fmt.Sprintf(" LIMIT %d", p.Limit.Max)
	}
	return fmt.Sprintf("SELECT %s FROM %s%s%s", cols, quoteIdent(tbl), where, limit), nil
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
func filterToSQL(node any) (string, error) {
	m, ok := node.(map[string]any)
	if !ok {
		return "", fmt.Errorf("filter must be an object")
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
		s, err := filterToSQL(inner)
		if err != nil {
			return "", err
		}
		return "NOT (" + s + ")", nil
	}
	return "", fmt.Errorf("invalid filter structure")
}

func renderList(join string, items []any) (string, error) {
	if len(items) == 0 {
		return "", fmt.Errorf("filter list must not be empty")
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		s, err := filterToSQL(it)
		if err != nil {
			return "", err
		}
		parts = append(parts, "("+s+")")
	}
	return strings.Join(parts, join), nil
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

func renderCondition(col, op string, val any) (string, error) {
	kw, ok := sqlOp[op]
	if !ok {
		return "", fmt.Errorf("unsupported filter op %q", op)
	}
	q := quoteIdent(col)
	switch op {
	case "=", "!=", "<", "<=", ">", ">=":
		lit, err := sqlLiteral(val)
		if err != nil {
			return "", err
		}
		return q + " " + kw + " " + lit, nil
	case "in", "not in":
		list, ok := val.([]any)
		if !ok || len(list) == 0 {
			return "", fmt.Errorf("op %s requires a non-empty list", op)
		}
		lits := make([]string, 0, len(list))
		for _, item := range list {
			lit, err := sqlLiteral(item)
			if err != nil {
				return "", err
			}
			lits = append(lits, lit)
		}
		return q + " " + kw + " (" + strings.Join(lits, ", ") + ")", nil
	case "between":
		list, ok := val.([]any)
		if !ok || len(list) != 2 {
			return "", fmt.Errorf("op between requires [lo, hi]")
		}
		lo, err := sqlLiteral(list[0])
		if err != nil {
			return "", err
		}
		hi, err := sqlLiteral(list[1])
		if err != nil {
			return "", err
		}
		return q + " " + kw + " " + lo + " AND " + hi, nil
	case "like":
		lit, err := sqlLiteral(val)
		if err != nil {
			return "", err
		}
		return q + " " + kw + " " + lit, nil
	case "is null", "is not null":
		return q + " " + kw, nil
	}
	return "", fmt.Errorf("unsupported filter op %q", op)
}

// sqlLiteral renders a JSON value as a MySQL literal.
func sqlLiteral(v any) (string, error) {
	switch t := v.(type) {
	case json.Number:
		return t.String(), nil
	case float64:
		return fmt.Sprintf("%v", t), nil
	case bool:
		if t {
			return "TRUE", nil
		}
		return "FALSE", nil
	case string:
		return "'" + strings.ReplaceAll(t, "'", "''") + "'", nil
	case nil:
		return "NULL", nil
	}
	return "", fmt.Errorf("unsupported literal type %T", v)
}

// quoteIdent quotes a MySQL identifier with backticks.
func quoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}
