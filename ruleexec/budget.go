package ruleexec

import (
	"fmt"
	"time"
)

// BudgetKind identifies which budget was exceeded.
type BudgetKind int

const (
	KindSteps BudgetKind = iota
	KindIterations
	KindDepth
	KindNesting
	KindTimeout
)

func (k BudgetKind) String() string {
	switch k {
	case KindSteps:
		return "steps"
	case KindIterations:
		return "iterations"
	case KindDepth:
		return "depth"
	case KindNesting:
		return "nesting"
	case KindTimeout:
		return "timeout"
	}
	return "unknown"
}

// BudgetError is returned when an execution budget is exceeded.
type BudgetError struct {
	Kind BudgetKind
	Used int64
	Max  int64
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("budget exceeded: %s %d > %d", e.Kind, e.Used, e.Max)
}

// Default budgets (to be published with the scheme spec; see
// docs/database-scheme-design.md §7).
const (
	DefaultMaxSteps      = 10000
	DefaultMaxIterations = 1000
	DefaultMaxDepth      = 64
	DefaultMaxNesting    = 64
)

// Budget enforces the execution budget for conditions and flows.
type Budget struct {
	MaxSteps      int64
	MaxIterations int64
	MaxDepth      int
	MaxNesting    int
	Deadline      time.Time

	steps      int64
	iterations int64
	nesting    int
}

// NewBudget returns a budget with the specification defaults.
func NewBudget() *Budget {
	return &Budget{
		MaxSteps:      DefaultMaxSteps,
		MaxIterations: DefaultMaxIterations,
		MaxDepth:      DefaultMaxDepth,
		MaxNesting:    DefaultMaxNesting,
	}
}

// Step charges one execution step.
func (b *Budget) Step() error {
	b.steps++
	if b.steps > b.MaxSteps {
		return &BudgetError{Kind: KindSteps, Used: b.steps, Max: b.MaxSteps}
	}
	if !b.Deadline.IsZero() && time.Now().After(b.Deadline) {
		return &BudgetError{Kind: KindTimeout}
	}
	return nil
}

// Iteration charges one loop iteration (accumulated across all loops).
func (b *Budget) Iteration() error {
	b.iterations++
	if b.iterations > b.MaxIterations {
		return &BudgetError{Kind: KindIterations, Used: b.iterations, Max: b.MaxIterations}
	}
	return nil
}

// Enter tracks recursion/nesting depth.
func (b *Budget) Enter(depth int) error {
	if depth > b.MaxDepth {
		return &BudgetError{Kind: KindDepth, Used: int64(depth), Max: int64(b.MaxDepth)}
	}
	b.nesting++
	if b.nesting > b.MaxNesting {
		return &BudgetError{Kind: KindNesting, Used: int64(b.nesting), Max: int64(b.MaxNesting)}
	}
	return nil
}

// Exit leaves a nesting level.
func (b *Budget) Exit() {
	if b.nesting > 0 {
		b.nesting--
	}
}

// Steps returns the current step count.
func (b *Budget) Steps() int64 { return b.steps }

// Iterations returns the current iteration count.
func (b *Budget) Iterations() int64 { return b.iterations }

// Stats returns the current counters (for audit output).
func (b *Budget) Stats() (steps, iterations int64) {
	return b.steps, b.iterations
}
