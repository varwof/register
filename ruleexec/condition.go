// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Condition is the structured condition AST (the "mini language").
// Leaf ops compare a resolved path against a value; and/or/not combine
// sub-conditions.
type Condition struct {
	Op     string      `json:"op"`
	Path   string      `json:"path,omitempty"`
	Value  any         `json:"value,omitempty"`
	Window []string    `json:"window,omitempty"` // between
	Items  []Condition `json:"items,omitempty"`  // and / or / not
}

func resolvePath(ctx map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var cur any = ctx
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// toNumber accepts NUMERIC values only (no string parsing): comparisons must
// not rely on implicit type coercion.
func toNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

// toBound parses a declared window bound ("1", "1000").  Window bounds are
// strings by AST design; only here is a string parsed as a number.
func toBound(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// EvalCondition evaluates a condition against a context map with a
// budget. Depth is tracked to prevent nesting-based abuse.
func EvalCondition(c Condition, ctx map[string]any, b *Budget, depth int) (bool, error) {
	if err := b.Step(); err != nil {
		return false, err
	}
	if err := b.Enter(depth); err != nil {
		return false, err
	}
	defer b.Exit()

	switch c.Op {
	case "and":
		for _, it := range c.Items {
			ok, err := EvalCondition(it, ctx, b, depth+1)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case "or":
		for _, it := range c.Items {
			ok, err := EvalCondition(it, ctx, b, depth+1)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case "not":
		if len(c.Items) != 1 {
			return false, fmt.Errorf("op not requires exactly 1 item")
		}
		ok, err := EvalCondition(c.Items[0], ctx, b, depth+1)
		return !ok, err
	case "is-null":
		// "no value present": either the path is absent from the context or
		// its value is explicitly null.  This is the ONLY way to test for a
		// missing/empty value: comparison operators never match NULL.
		v, ok := resolvePath(ctx, c.Path)
		if !ok {
			return true, nil
		}
		return v == nil, nil
	default:
		if !knownConditionOps[c.Op] {
			return false, fmt.Errorf("unknown condition op %q", c.Op)
		}
		v, ok := resolvePath(ctx, c.Path)
		if !ok {
			return false, fmt.Errorf("condition path %q not found", c.Path)
		}
		return evalLeaf(c.Op, v, c.Value, c.Window)
	}
}

func evalLeaf(op string, got, want any, window []string) (bool, error) {
	switch op {
	case "eq":
		// NULL is never equal (SQL: `col = NULL` matches no rows); use
		// is-null to test for a missing/empty value.
		if got == nil || want == nil {
			return false, nil
		}
		return reflect.DeepEqual(normalizeNum(got), normalizeNum(want)), nil
	case "neq":
		// NULL is never unequal either (SQL: `col <> NULL` matches no rows).
		if got == nil || want == nil {
			return false, nil
		}
		return !reflect.DeepEqual(normalizeNum(got), normalizeNum(want)), nil
	case "lt", "lte", "gt", "gte":
		if got == nil || want == nil {
			return false, nil // comparison with NULL is never true
		}
		gf, ok1 := toNumber(got)
		wf, ok2 := toNumber(want)
		if !ok1 || !ok2 {
			return false, fmt.Errorf("op %s requires numeric operands", op)
		}
		switch op {
		case "lt":
			return gf < wf, nil
		case "lte":
			return gf <= wf, nil
		case "gt":
			return gf > wf, nil
		default:
			return gf >= wf, nil
		}
	case "in":
		list, ok := want.([]any)
		if !ok {
			return false, fmt.Errorf("op in requires a list value")
		}
		if got == nil {
			return false, nil // NULL is in no list (SQL: `NULL IN (...)` is unknown)
		}
		for _, item := range list {
			if item == nil {
				continue // null list elements never match (also rejected at load time)
			}
			if reflect.DeepEqual(normalizeNum(got), normalizeNum(item)) {
				return true, nil
			}
		}
		return false, nil
	case "between":
		if len(window) != 2 {
			return false, fmt.Errorf("op between requires window [lo, hi]")
		}
		if got == nil {
			return false, nil // comparison with NULL is never true
		}
		gf, ok1 := toNumber(got)
		lo, ok2 := toBound(window[0])
		hi, ok3 := toBound(window[1])
		if !ok1 || !ok2 || !ok3 {
			return false, fmt.Errorf("op between requires numeric operands")
		}
		return gf >= lo && gf <= hi, nil
	case "is-null":
		return got == nil, nil
	}
	return false, fmt.Errorf("unknown condition op %q", op)
}

// normalizeNum normalizes NUMERIC values (int/float/json.Number) so that
// 500 and 500.0 compare equal.  It deliberately does NOT convert strings:
// "500" and 500 are different values (no implicit type coercion).
func normalizeNum(v any) any {
	if n, ok := toNumber(v); ok {
		return n
	}
	return v
}
