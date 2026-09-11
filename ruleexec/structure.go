// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"fmt"
	"regexp"
	"strings"
)

// knownConditionOps is the fixed mini-language operator set.
var knownConditionOps = map[string]bool{
	"and": true, "or": true, "not": true,
	"eq": true, "neq": true, "lt": true, "lte": true, "gt": true, "gte": true,
	"in": true, "between": true, "is-null": true,
}

// knownStepKinds is the fixed flow step set.
var knownStepKinds = map[string]bool{
	"op": true, "if": true, "seq": true,
}

var versionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ValidateStructure performs schema-level validation of a rule:
// field formats, condition operators, flow step kinds and nesting.
func ValidateStructure(r *Rule) error {
	if len(r.RuleID) == 0 || len(r.RuleID) > 128 {
		return fmt.Errorf("rule_id must be 1..128 chars")
	}
	if !versionRe.MatchString(r.Version) {
		return fmt.Errorf("version must be semver x.y.z")
	}
	if !strings.Contains(r.Scheme, "/") {
		return fmt.Errorf("scheme must be vendor/product")
	}
	if r.Conditions != nil {
		if err := checkCondition(r.Conditions); err != nil {
			return fmt.Errorf("conditions: %w", err)
		}
	}
	if r.Flow != nil {
		if err := checkSteps(r.Flow.Steps); err != nil {
			return fmt.Errorf("flow: %w", err)
		}
	}
	return nil
}

func checkCondition(c *Condition) error {
	if c == nil {
		return nil
	}
	switch c.Op {
	case "eq", "neq", "lt", "lte", "gt", "gte":
		if c.Value == nil && c.Path != "" {
			return fmt.Errorf("condition %s: comparing to null is not supported; use \"is-null\" (or \"not\" + \"is-null\")", c.Op)
		}
	case "in":
		if list, ok := c.Value.([]any); ok {
			for _, it := range list {
				if it == nil {
					return fmt.Errorf("condition in: null elements are not allowed; use \"is-null\" per value")
				}
			}
		}
	}
	if c == nil {
		return fmt.Errorf("nil condition")
	}
	if !knownConditionOps[c.Op] {
		return fmt.Errorf("unknown condition op %q", c.Op)
	}
	for i := range c.Items {
		if err := checkCondition(&c.Items[i]); err != nil {
			return err
		}
	}
	return nil
}

func checkSteps(steps []Step) error {
	for i := range steps {
		st := &steps[i]
		if !knownStepKinds[st.Kind] {
			return fmt.Errorf("unknown step kind %q", st.Kind)
		}
		if st.Kind == "if" && st.Condition == nil {
			return fmt.Errorf("if step %q requires a condition", st.Name)
		}
		if st.Condition != nil {
			if err := checkCondition(st.Condition); err != nil {
				return err
			}
		}
		if err := checkSteps(st.Then); err != nil {
			return err
		}
		if err := checkSteps(st.Else); err != nil {
			return err
		}
		if err := checkSteps(st.Steps); err != nil {
			return err
		}
	}
	return nil
}
