// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

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
	MaxSteps   int `json:"max_steps"`
	MaxDepth   int `json:"max_depth"`
	MaxNesting int `json:"max_nesting"`
}

// Published ceilings (see budget-defaults.json).  Implementations MUST NOT
// relax these values; a file that asks for more is rejected.
const (
	MaxStepsCeiling   = 10000
	MaxDepthCeiling   = 64
	MaxNestingCeiling = 64
)

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
	if d.MaxSteps <= 0 || d.MaxDepth <= 0 || d.MaxNesting <= 0 {
		return nil, fmt.Errorf("invalid budget defaults")
	}
	if d.MaxSteps > MaxStepsCeiling ||
		d.MaxDepth > MaxDepthCeiling || d.MaxNesting > MaxNestingCeiling {
		return nil, fmt.Errorf("budget defaults must not relax published ceilings")
	}
	return &d, nil
}

// BudgetFromDefaults builds a Budget from published defaults.
func BudgetFromDefaults(d *BudgetDefaults) *Budget {
	b := NewBudget()
	b.MaxSteps = int64(d.MaxSteps)
	b.MaxDepth = d.MaxDepth
	b.MaxNesting = d.MaxNesting
	return b
}
