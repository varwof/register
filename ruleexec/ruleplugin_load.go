package ruleexec

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"path/filepath"

	pki "github.com/varwof/types"
	"github.com/varwof/register"
)

// LoadRulePlugin loads a published (PKCS#7 signed) rule file and
// builds the gateway phase-two plugin for it. Signature verification
// is mandatory (fail-closed): a tampered or unsigned rule is rejected.
// A fresh execution budget is created per plugin so that counters are
// never shared across executions.
func LoadRulePlugin(rulePath string, trustRoots []*x509.Certificate, handler OpHandler) (*RulePlugin, error) {
	if err := register.VerifyCapabilityPKCS7(rulePath, trustRoots); err != nil {
		return nil, fmt.Errorf("rule %s: signature verification failed: %w", rulePath, err)
	}
	rule, err := LoadRule(rulePath)
	if err != nil {
		return nil, err
	}
	if err := ValidateStructure(rule); err != nil {
		return nil, fmt.Errorf("rule %s: %w", rulePath, err)
	}
	return NewRulePlugin(rule.Scheme, rule, NewBudget(), handler), nil
}

// RegisterRulePluginsFromDir loads signed rules from a published rule
// directory (outDir/<scheme>/default.json [+ .p7s], as produced by
// PublishRules) and registers one RulePlugin per scheme into reg.
// Returns the registered scheme list. Any signature or validation
// failure aborts the whole registration (fail-closed).
func RegisterRulePluginsFromDir(reg *pki.PluginRegistry, dir string, trustRoots []*x509.Certificate, handler OpHandler) ([]string, error) {
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
		plugin, err := LoadRulePlugin(path, trustRoots, handler)
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
