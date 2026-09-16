// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/varwof/register"
	pki "github.com/varwof/types"
)

// LoadRulePlugin loads a published (PKCS#7 signed) rule file and
// builds the gateway phase-two plugin for it. Signature verification
// and registry validation are mandatory (fail-closed): a tampered,
// unsigned, or parameters-contract-violating rule is rejected.
// A fresh execution budget is created per plugin so that counters are
// never shared across executions.
func LoadRulePlugin(rulePath string, trustRoots []*x509.Certificate, handler OpHandler, reg *register.Registry) (*RulePlugin, error) {
	rule, err := loadAuthorizedRule(rulePath, trustRoots, reg)
	if err != nil {
		return nil, err
	}
	return NewRulePlugin(rule.Scheme, rule, NewBudget(), handler), nil
}

// loadAuthorizedRule verifies the detached PKCS#7 signature, parses the rule,
// validates its structure AND its parameters against the registry contract,
// and enforces the publication boundary: the rule's capability must be
// covered by the SIGNER's own AIC grant.  Any failure is fatal for the rule
// (fail-closed).
func loadAuthorizedRule(rulePath string, trustRoots []*x509.Certificate, reg *register.Registry) (*Rule, error) {
	if reg == nil {
		return nil, fmt.Errorf("rule %s: registry is required (Rule.Validate must fail closed)", rulePath)
	}
	signer, err := register.VerifyCapabilityPKCS7Cert(rulePath, trustRoots)
	if err != nil {
		return nil, fmt.Errorf("rule %s: signature verification failed: %w", rulePath, err)
	}
	rule, err := LoadRule(rulePath)
	if err != nil {
		return nil, err
	}
	if err := ValidateStructure(rule); err != nil {
		return nil, fmt.Errorf("rule %s: %w", rulePath, err)
	}
	if err := rule.Validate(reg); err != nil {
		return nil, fmt.Errorf("rule %s: %w", rulePath, err)
	}
	if err := RuleWithinSignerGrant(rule, signer); err != nil {
		return nil, fmt.Errorf("rule %s: %w", rulePath, err)
	}
	return rule, nil
}

// RegisterRulePluginsFromDir loads signed rules from a published rule
// directory (outDir/<scheme>/default.json [+ .p7s], as produced by
// PublishRules) and registers one RulePlugin per scheme into reg.
// Returns the registered scheme list. Any signature or validation
// failure aborts the whole registration (fail-closed).  reg is the
// gateway registry; sreg is the CLC scheme registry used by
// Rule.Validate (fail closed, must not be nil).
func RegisterRulePluginsFromDir(reg *pki.PluginRegistry, dir string, trustRoots []*x509.Certificate, handler OpHandler, sreg *register.Registry) ([]string, error) {
	if reg == nil || sreg == nil {
		return nil, fmt.Errorf("register rules: plugin registry and scheme registry are required")
	}
	var schemes []string
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() || filepath.Base(path) != "default.json" {
			return nil
		}
		rel, err := filepath.Rel(dir, filepath.Dir(path))
		if err != nil {
			return err
		}
		scheme := filepath.ToSlash(rel)
		// Schemes already present (e.g., configured by capability_plugins)
		// keep precedence; rules never overwrite them.
		if _, err := reg.Find(scheme); err == nil {
			return nil
		}
		plugin, err := LoadRulePlugin(path, trustRoots, handler, sreg)
		if err != nil {
			return fmt.Errorf("rule %s: %w", path, err)
		}
		if err := reg.Register(plugin); err != nil {
			return err
		}
		schemes = append(schemes, scheme)
		return nil
	})
	return schemes, err
}
