// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	pki "github.com/varwof/types"

	"github.com/varwof/register/semantics"
)

// RuleWithinSignerGrant enforces the PUBLICATION BOUNDARY of a signed rule:
// the capability a rule declares MUST be covered by the signer's own AIC
// grant (CLC-v1 entailment, semantics.Entails), and every constraint the rule
// declares MUST also be declared by the signer.
//
// Without this check a holder of any trusted signing certificate could publish
// a rule that exceeds its own authority.  The check is fail-closed: a signer
// without an AIC extension, or without a covering capability, is rejected.
func RuleWithinSignerGrant(rule *Rule, signer *x509.Certificate) error {
	if rule == nil || signer == nil {
		return fmt.Errorf("signer grant: rule and signer certificate are required")
	}
	aic, err := pki.ParseAIC(signer)
	if err != nil {
		return fmt.Errorf("signer grant: parse AIC: %w", err)
	}
	if aic == nil {
		return fmt.Errorf("signer grant: signer certificate has no AIC extension; cannot authorize rule publication")
	}

	op := semantics.Operation{ID: rule.Scheme + ":" + rule.Capability}
	if len(rule.Params) > 0 {
		var params map[string]any
		if err := json.Unmarshal(rule.Params, &params); err != nil {
			return fmt.Errorf("signer grant: rule params: %w", err)
		}
		op.Params = params
	}

	for _, cap := range aic.Capabilities {
		grantID := cap.FullID()
		if !coversID(grantID, op.ID) {
			continue
		}
		grant := semantics.Grant{ID: grantID}
		if len(cap.Parameters) > 0 {
			var gp map[string]any
			if err := json.Unmarshal(cap.Parameters, &gp); err != nil {
				return fmt.Errorf("signer grant: signer capability %s params: %w", grantID, err)
			}
			grant.Params = gp
		}
		if res := semantics.Entails(grant, op); res.Entails {
			return ruleConstraintsWithinSigner(rule, aic)
		}
	}
	return fmt.Errorf("signer grant: rule capability %s is not covered by the signer's AIC grant", op.ID)
}

// coversID reports whether a granted capability identifier covers the rule's
// capability identifier (literal match or trailing wildcard, per CLC-v1 §6.1).
func coversID(grantID, opID string) bool {
	if grantID == opID {
		return true
	}
	if strings.HasSuffix(grantID, ":*") {
		prefix := strings.TrimSuffix(grantID, "*")
		return strings.HasPrefix(opID, prefix) && len(opID) > len(prefix)
	}
	return false
}

// ruleConstraintsWithinSigner requires every rule constraint type to appear in
// the signer's authorization constraints.  Scheme spelling is normalized
// (constraint / constraint-v1 / varwof/constraint-v1 refer to the same
// namespace), so the match is by constraint ID.
func ruleConstraintsWithinSigner(rule *Rule, aic *pki.AIC) error {
	for _, rc := range rule.Constraints {
		found := false
		for _, sc := range aic.AuthorizationConstraints {
			if sc.CapabilityId == rc.ID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("signer grant: rule constraint %s:%s is not declared by the signer", rc.Scheme, rc.ID)
		}
	}
	return nil
}
