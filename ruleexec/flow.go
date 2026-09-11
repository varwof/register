// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"fmt"
)

// Flow is the minimal workflow AST (Python/C-style flow control).
type Flow struct {
	Steps []Step `json:"steps"`
}

// Step kinds: op | if | seq
type Step struct {
	Name      string     `json:"name,omitempty"`
	Kind      string     `json:"kind"`
	Op        string     `json:"op,omitempty"`
	Condition *Condition `json:"condition,omitempty"`
	Then      []Step     `json:"then,omitempty"`
	Else      []Step     `json:"else,omitempty"`
	Steps     []Step     `json:"steps,omitempty"`
}

// FlowContext carries task-local variables, the request facts, and the
// operation handler (the gateway's fixed capability executor).
type FlowContext struct {
	Vars    map[string]any
	Request map[string]any
	Handler OpHandler
}

// OpHandler executes a named operation (e.g. "db:select"). The
// returned map is merged into task variables.
type OpHandler func(op string, vars, req map[string]any) (map[string]any, error)

// RunFlow executes a flow with the given budget.
func RunFlow(f Flow, ctx *FlowContext, b *Budget) error {
	return runSteps(f.Steps, ctx, b, 0)
}

func runSteps(steps []Step, ctx *FlowContext, b *Budget, depth int) error {
	if err := b.Enter(depth); err != nil {
		return err
	}
	defer b.Exit()

	for _, st := range steps {
		if err := b.Step(); err != nil {
			return err
		}
		switch st.Kind {
		case "op":
			out, err := ctx.Handler(st.Op, ctx.Vars, ctx.Request)
			if err != nil {
				return fmt.Errorf("op %s: %w", st.Op, err)
			}
			for k, v := range out {
				ctx.Vars[k] = v
			}
		case "if":
			evalCtx := evalContext(ctx)
			ok, err := EvalCondition(*st.Condition, evalCtx, b, depth+1)
			if err != nil {
				return err
			}
			if ok {
				if err := runSteps(st.Then, ctx, b, depth+1); err != nil {
					return err
				}
			} else if err := runSteps(st.Else, ctx, b, depth+1); err != nil {
				return err
			}
		case "seq":
			if err := runSteps(st.Steps, ctx, b, depth+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown step kind %q", st.Kind)
		}
	}
	return nil
}

// CheckStaticBounds walks a flow BEFORE execution and enforces a zero-cost
// structural rule: nesting depth must fit the budget.  Loops and retries were
// removed from the execution language (2026-09-10), so a flow is a finite tree
// of op / if / seq: termination is structural and a single authorization can
// trigger at most one execution of each operation (no amplification factor).
func CheckStaticBounds(f Flow, b *Budget) error {
	return walkBounds(f.Steps, b, 1)
}

func walkBounds(steps []Step, b *Budget, depth int) error {
	if depth > b.MaxNesting {
		return fmt.Errorf("static bound check: nesting depth %d > budget %d", depth, b.MaxNesting)
	}
	for _, st := range steps {
		switch st.Kind {
		case "if":
			if err := walkBounds(st.Then, b, depth+1); err != nil {
				return err
			}
			if err := walkBounds(st.Else, b, depth+1); err != nil {
				return err
			}
		case "seq":
			if err := walkBounds(st.Steps, b, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// evalContext merges request facts and task variables for condition
// evaluation: request.* paths and top-level variable names both work.
func evalContext(ctx *FlowContext) map[string]any {
	m := make(map[string]any, len(ctx.Vars)+1)
	for k, v := range ctx.Vars {
		m[k] = v
	}
	m["request"] = ctx.Request
	return m
}
