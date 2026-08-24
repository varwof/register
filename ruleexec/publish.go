package ruleexec

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/varwof/register"
)

// RuleVersion is a parsed v<major>.<minor>.json version.
type RuleVersion struct{ Major, Minor int }

// SchemePublish describes one published rule scheme.
type SchemePublish struct {
	Latest string   `json:"latest"`
	Files  []string `json:"files"`
}

// PublishManifest is the publication manifest.
type PublishManifest struct {
	Schemes map[string]SchemePublish `json:"schemes"`
}

var ruleVersionRe = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.json$`)

// PublishRules publishes rule files from rulesDir into outDir:
//
//	rulesDir/<scheme>/v<maj>.<min>.json
//
// Each rule is validated (structure) and PKCS#7 signed. default.json
// is published as a byte-identical copy of the highest minor version,
// so its .p7s detached signature stays valid without re-signing.
// certPath/keyPath are the signer certificate/key (PEM).
func PublishRules(rulesDir, outDir, certPath, keyPath string) (*PublishManifest, error) {
	m := &PublishManifest{Schemes: map[string]SchemePublish{}}

	// Collect versions grouped by scheme. The layout follows the
	// register convention: rulesDir/<vendor>/<product>-v<major>/vX.Y.json,
	// so the scheme key is the relative directory ("vendor/product").
	byScheme := map[string][]RuleVersion{}
	if err := filepath.WalkDir(rulesDir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		mm := ruleVersionRe.FindStringSubmatch(filepath.Base(path))
		if mm == nil {
			return nil
		}
		rel, err := filepath.Rel(rulesDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		major, _ := strconv.Atoi(mm[1])
		minor, _ := strconv.Atoi(mm[2])
		scheme := filepath.ToSlash(rel)
		byScheme[scheme] = append(byScheme[scheme], RuleVersion{Major: major, Minor: minor})
		return nil
	}); err != nil {
		return nil, err
	}

	schemes := make([]string, 0, len(byScheme))
	for scheme := range byScheme {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	for _, scheme := range schemes {
		versions := byScheme[scheme]
		src := filepath.Join(rulesDir, filepath.FromSlash(scheme))
		sort.Slice(versions, func(i, j int) bool {
			if versions[i].Major != versions[j].Major {
				return versions[i].Major < versions[j].Major
			}
			return versions[i].Minor < versions[j].Minor
		})
		dst := filepath.Join(outDir, scheme)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return nil, err
		}
		var files []string
		for _, ver := range versions {
			name := fmt.Sprintf("v%d.%d.json", ver.Major, ver.Minor)
			if err := copyAndSign(filepath.Join(src, name), filepath.Join(dst, name), certPath, keyPath); err != nil {
				return nil, err
			}
			files = append(files, name)
		}
		latest := files[len(files)-1]
		// default.json = byte-identical copy of the latest compatible
		// (highest minor) version.
		if err := copyAndSign(filepath.Join(src, latest), filepath.Join(dst, "default.json"), certPath, keyPath); err != nil {
			return nil, err
		}
		m.Schemes[scheme] = SchemePublish{Latest: latest, Files: files}
	}
	return m, nil
}

func listRuleVersions(dir string) ([]RuleVersion, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []RuleVersion
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		mm := ruleVersionRe.FindStringSubmatch(e.Name())
		if mm == nil {
			continue
		}
		major, _ := strconv.Atoi(mm[1])
		minor, _ := strconv.Atoi(mm[2])
		out = append(out, RuleVersion{Major: major, Minor: minor})
	}
	return out, nil
}

// copyAndSign copies a rule file (byte-identical) and signs it with
// PKCS#7 detached signature (register.SignCapability).
func copyAndSign(src, dst, certPath, keyPath string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	rule, err := LoadRuleBytes(data)
	if err != nil {
		return fmt.Errorf("rule %s: %w", src, err)
	}
	if err := ValidateStructure(rule); err != nil {
		return fmt.Errorf("rule %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	if err := register.SignCapability(certPath, keyPath, dst, dst+".p7s"); err != nil {
		return fmt.Errorf("sign %s: %w", dst, err)
	}
	return nil
}

// PublishManifestJSON renders the manifest for output.
func PublishManifestJSON(m *PublishManifest) (string, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
