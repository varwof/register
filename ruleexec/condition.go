// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Condition is the structured condition AST (the "mini language").
// Leaf ops compare a resolved path against a value; and/or/not combine
// sub-conditions.
type Condition struct {
	Op     string      `json:"op"`
	Path   string      `json:"path,omitempty"`
	Value  any         `json:"value,omitempty"`
	Window []string    `json:"window,omitempty"` // time-in / between
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

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
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
		v, ok := resolvePath(ctx, c.Path)
		if !ok {
			return true, nil // missing path == null
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
		return reflect.DeepEqual(normalizeNum(got), normalizeNum(want)), nil
	case "neq":
		return !reflect.DeepEqual(normalizeNum(got), normalizeNum(want)), nil
	case "lt", "lte", "gt", "gte":
		gf, ok1 := toFloat(got)
		wf, ok2 := toFloat(want)
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
		for _, item := range list {
			if reflect.DeepEqual(normalizeNum(got), normalizeNum(item)) {
				return true, nil
			}
		}
		return false, nil
	case "contains":
		gs, ok1 := got.(string)
		ws, ok2 := want.(string)
		if !ok1 || !ok2 {
			return false, fmt.Errorf("op contains requires string operands")
		}
		return strings.Contains(gs, ws), nil
	case "between":
		if len(window) != 2 {
			return false, fmt.Errorf("op between requires window [lo, hi]")
		}
		gf, ok1 := toFloat(got)
		lo, ok2 := toFloat(window[0])
		hi, ok3 := toFloat(window[1])
		if !ok1 || !ok2 || !ok3 {
			return false, fmt.Errorf("op between requires numeric operands")
		}
		return gf >= lo && gf <= hi, nil
	case "time-in":
		if len(window) != 2 {
			return false, fmt.Errorf("op time-in requires window [start, end] HH:MM")
		}
		ts, ok := got.(string)
		if !ok {
			return false, fmt.Errorf("op time-in requires an RFC3339 time string")
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return false, fmt.Errorf("op time-in: %w", err)
		}
		cur := t.UTC().Hour()*60 + t.UTC().Minute()
		start, err1 := parseHHMM(window[0])
		end, err2 := parseHHMM(window[1])
		if err1 != nil || err2 != nil {
			return false, fmt.Errorf("op time-in: invalid window")
		}
		if start <= end {
			return cur >= start && cur <= end, nil
		}
		// overnight window
		return cur >= start || cur <= end, nil
	case "is-null":
		return got == nil, nil
	}
	return false, fmt.Errorf("unknown condition op %q", op)
}

func normalizeNum(v any) any {
	if n, ok := toFloat(v); ok {
		return n
	}
	return v
}

func parseHHMM(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("bad HH:MM %q", s)
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("bad HH:MM %q", s)
	}
	return h*60 + m, nil
}
