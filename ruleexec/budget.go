// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"fmt"
	"time"
)

// BudgetKind identifies which budget was exceeded.
type BudgetKind int

const (
	KindSteps BudgetKind = iota
	KindDepth
	KindNesting
	KindTimeout
)

func (k BudgetKind) String() string {
	switch k {
	case KindSteps:
		return "steps"
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
	DefaultMaxSteps   = 10000
	DefaultMaxDepth   = 64
	DefaultMaxNesting = 64
)

// Budget enforces the execution budget for conditions and flows.
// Since loops and retries were removed (2026-09-10) a flow is a finite tree,
// so the budget is a defence-in-depth guard rather than the termination argument.
type Budget struct {
	MaxSteps   int64
	MaxDepth   int
	MaxNesting int
	Deadline   time.Time

	steps   int64
	nesting int
}

// NewBudget returns a budget with the specification defaults.
func NewBudget() *Budget {
	return &Budget{
		MaxSteps:   DefaultMaxSteps,
		MaxDepth:   DefaultMaxDepth,
		MaxNesting: DefaultMaxNesting,
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

// Stats returns the current counters (for audit output).
func (b *Budget) Stats() (steps int64) {
	return b.steps
}
