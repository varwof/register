// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"fmt"
	"time"
)

// DecisionInput mirrors the facts a gateway phase-two plugin receives
// after AIC validation: EffectiveCaps (P∩C) plus request context
// (see gateway-core AdmissionResult.EffectiveCaps).
type DecisionInput struct {
	AgentID       string
	PrincipalID   string
	Mode          string
	EffectiveCaps []string
	Request       map[string]any
	Now           time.Time
}

// Decision is the phase-two outcome.
type Decision struct {
	Allow      bool
	Reason     string
	Steps      int64
	Iterations int64
}

// PhaseTwo is the policy-executor contract the gateway phase-two
// plugin slot expects (per-scheme routing after EffectiveCaps).
type PhaseTwo interface {
	Decide(in DecisionInput) (*Decision, error)
}

// RuleExecutor binds a signed rule to the phase-two contract.
type RuleExecutor struct {
	Rule    *Rule
	Budget  *Budget
	Handler OpHandler
}

// Decide validates the rule structure, runs the static bounds
// pre-check, evaluates the conditions against the request, and runs
// the flow. Authorization itself stays in the AIC layer; this
// executor only implements the rule's conditions and orchestration.
func (e *RuleExecutor) Decide(in DecisionInput) (*Decision, error) {
	if err := ValidateStructure(e.Rule); err != nil {
		return nil, fmt.Errorf("phase2: invalid rule: %w", err)
	}
	if e.Rule.Flow != nil {
		if err := CheckStaticBounds(*e.Rule.Flow, e.Budget); err != nil {
			return nil, fmt.Errorf("phase2: static bounds: %w", err)
		}
	}
	if e.Rule.Conditions != nil {
		ctx := map[string]any{"request": in.Request}
		ok, err := EvalCondition(*e.Rule.Conditions, ctx, e.Budget, 0)
		if err != nil {
			return nil, fmt.Errorf("phase2: conditions: %w", err)
		}
		if !ok {
			return &Decision{Allow: false, Reason: "conditions not satisfied"}, nil
		}
	}
	if e.Rule.Flow != nil {
		fc := &FlowContext{
			Vars:    map[string]any{},
			Request: in.Request,
			Handler: e.Handler,
		}
		if err := RunFlow(*e.Rule.Flow, fc, e.Budget); err != nil {
			return nil, fmt.Errorf("phase2: flow: %w", err)
		}
	}
	steps, iters := e.Budget.Stats()
	return &Decision{Allow: true, Steps: steps, Iterations: iters}, nil
}
