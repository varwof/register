package ruleexec

import (
	"encoding/json"
	"fmt"
	"os"
)

// BudgetDefaults is the published execution budget, distributed with
// the scheme spec (see budget-defaults.json and
// docs/database-scheme-design.md §7). Implementations MUST NOT relax
// these values.
type BudgetDefaults struct {
	MaxSteps      int   `json:"max_steps"`
	MaxIterations int   `json:"max_iterations"`
	MaxDepth      int   `json:"max_depth"`
	MaxNesting    int   `json:"max_nesting"`
	WallClockMs   int64 `json:"wall_clock_ms"`
}

// LoadBudgetDefaults reads a published budget-defaults.json.
func LoadBudgetDefaults(path string) (*BudgetDefaults, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d BudgetDefaults
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if d.MaxSteps <= 0 || d.MaxIterations <= 0 || d.MaxDepth <= 0 || d.MaxNesting <= 0 {
		return nil, fmt.Errorf("invalid budget defaults")
	}
	return &d, nil
}

// BudgetFromDefaults builds a Budget from published defaults.
func BudgetFromDefaults(d *BudgetDefaults) *Budget {
	b := NewBudget()
	b.MaxSteps = int64(d.MaxSteps)
	b.MaxIterations = int64(d.MaxIterations)
	b.MaxDepth = d.MaxDepth
	b.MaxNesting = d.MaxNesting
	return b
}
