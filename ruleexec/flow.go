package ruleexec

import (
	"errors"
	"fmt"
)

// Flow is the minimal workflow AST (Python/C-style flow control).
type Flow struct {
	Steps []Step `json:"steps"`
}

// Step kinds: op | if | while | for | retry | seq | break | continue
type Step struct {
	Name       string     `json:"name,omitempty"`
	Kind       string     `json:"kind"`
	Op         string     `json:"op,omitempty"`
	Condition  *Condition `json:"condition,omitempty"`
	Then       []Step     `json:"then,omitempty"`
	Else       []Step     `json:"else,omitempty"`
	Var        string     `json:"var,omitempty"`
	From       int        `json:"from,omitempty"`
	To         int        `json:"to,omitempty"`
	MaxRetries int        `json:"max_retries,omitempty"`
	Steps      []Step     `json:"steps,omitempty"`
	Do         []Step     `json:"do,omitempty"`
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

var (
	errBreak    = errors.New("flow: break")
	errContinue = errors.New("flow: continue")
)

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
		case "while":
			for {
				if err := b.Iteration(); err != nil {
					return err
				}
				ok, err := EvalCondition(*st.Condition, evalContext(ctx), b, depth+1)
				if err != nil {
					return err
				}
				if !ok {
					break
				}
				err = runSteps(st.Do, ctx, b, depth+1)
				if err == errBreak {
					break
				}
				if err == errContinue {
					continue
				}
				if err != nil {
					return err
				}
			}
		case "for":
			for i := st.From; i < st.To; i++ {
				if err := b.Iteration(); err != nil {
					return err
				}
				if st.Var != "" {
					ctx.Vars[st.Var] = i
				}
				err := runSteps(st.Do, ctx, b, depth+1)
				if err == errBreak {
					break
				}
				if err == errContinue {
					continue
				}
				if err != nil {
					return err
				}
			}
		case "retry":
			var last error
			for attempt := 0; attempt <= st.MaxRetries; attempt++ {
				if err := b.Iteration(); err != nil {
					return err
				}
				last = runSteps(st.Steps, ctx, b, depth+1)
				if last == nil {
					break
				}
				if last == errBreak || last == errContinue {
					return last
				}
			}
			if last != nil {
				return fmt.Errorf("retry %s exhausted after %d attempts: %w", st.Name, st.MaxRetries+1, last)
			}
		case "seq":
			if err := runSteps(st.Steps, ctx, b, depth+1); err != nil {
				return err
			}
		case "break":
			return errBreak
		case "continue":
			return errContinue
		default:
			return fmt.Errorf("unknown step kind %q", st.Kind)
		}
	}
	return nil
}

// CheckStaticBounds walks a flow BEFORE execution and enforces two
// zero-cost structural rules:
//
//  1. loop nesting is forbidden (a while/for must not appear inside
//     another loop, even transitively through if/retry/seq) -- this
//     eliminates iteration-explosion by construction;
//  2. statically-visible loop/retry bounds must fit the budget.
//
// if <-> while nesting remains allowed (if inside a loop, or a loop
// inside an if branch).
func CheckStaticBounds(f Flow, b *Budget) error {
	return walkBounds(f.Steps, b, 0)
}

func walkBounds(steps []Step, b *Budget, loopDepth int) error {
	for _, st := range steps {
		switch st.Kind {
		case "for", "while":
			if loopDepth >= 1 {
				return fmt.Errorf("static bound check: nested loop %q (loop nesting is forbidden)", st.Name)
			}
			if st.Kind == "for" {
				if n := st.To - st.From; n > int(b.MaxIterations) {
					return fmt.Errorf("static bound check: for loop %q iterates %d times > budget %d", st.Name, n, b.MaxIterations)
				}
			}
			if err := walkBounds(st.Do, b, loopDepth+1); err != nil {
				return err
			}
		case "if":
			if err := walkBounds(st.Then, b, loopDepth); err != nil {
				return err
			}
			if err := walkBounds(st.Else, b, loopDepth); err != nil {
				return err
			}
		case "retry":
			if st.MaxRetries+1 > int(b.MaxIterations) {
				return fmt.Errorf("static bound check: retry %q allows %d attempts > budget %d", st.Name, st.MaxRetries+1, b.MaxIterations)
			}
			if err := walkBounds(st.Steps, b, loopDepth); err != nil {
				return err
			}
		case "seq":
			if err := walkBounds(st.Steps, b, loopDepth); err != nil {
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
