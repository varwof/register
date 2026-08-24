package ruleexec

import (
	"fmt"

	pki "github.com/varwof/types"
)

// RulePlugin adapts a signed rule to the gateway-core phase-two plugin
// slot (CapabilityPlugin). The admission pipeline calls Execute once
// per effective capability whose scheme matches Scheme(); a
// PluginDeny or error denies the connection (fail-closed).
type RulePlugin struct {
	scheme string
	exec   *RuleExecutor
}

// NewRulePlugin builds a phase-two plugin executing rule for scheme.
func NewRulePlugin(scheme string, rule *Rule, budget *Budget, handler OpHandler) *RulePlugin {
	return &RulePlugin{scheme: scheme, exec: &RuleExecutor{Rule: rule, Budget: budget, Handler: handler}}
}

// Scheme returns the capability scheme this plugin serves.
func (p *RulePlugin) Scheme() string { return p.scheme }

// Execute maps gateway-core PluginContext facts into a DecisionInput and
// runs the rule executor (structure -> static bounds -> conditions ->
// flow). Authorization stays in the AIC layer; this implements the
// rule's conditions and orchestration only.
func (p *RulePlugin) Execute(cap *pki.Capability, ctx *pki.PluginContext) (*pki.PluginResult, error) {
	req := MapHTTPRequest(ctx)
	eff := []string{cap.FullID()}
	if ctx.AIC != nil {
		for _, c := range ctx.AIC.Capabilities {
			eff = append(eff, c.SchemeId+":"+c.CapabilityId)
		}
	}
	dec, err := p.exec.Decide(DecisionInput{
		AgentID:       ctx.AgentId,
		PrincipalID:   ctx.ClientCN,
		Mode:          "authorized",
		EffectiveCaps: eff,
		Request:       req,
	})
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", p.exec.Rule.RuleID, err)
	}
	if !dec.Allow {
		return &pki.PluginResult{Decision: pki.PluginDeny, Reason: dec.Reason}, nil
	}
	return &pki.PluginResult{
		Decision: pki.PluginAllow,
		Reason:   fmt.Sprintf("rule %s ok", p.exec.Rule.RuleID),
		Metadata: map[string]string{
			"steps":      fmt.Sprintf("%d", dec.Steps),
			"iterations": fmt.Sprintf("%d", dec.Iterations),
		},
	}, nil
}
