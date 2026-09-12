// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestIntersectionProperty is the executable form of principle P11
// ("composition narrows only", CLC-v1 §7 rules 2/5/6).  It runs a deterministic
// case list shared with the Python implementation:
//
//	for every case
//	  * Intersect either denies with a normative reason code, or
//	  * returns a grant covered by *every* source, and
//	  * the result does not depend on the order of the sources.
//
// The case list lives in the capability repository
// (data/_vectors/clc-v1/property-cases.json); override with CLC_PROPERTY_CASES.

type propertyCase struct {
	ID      string  `json:"id"`
	Sources []Grant `json:"sources"`
	Note    string  `json:"note"`
}

type propertyFile struct {
	Cases []propertyCase `json:"cases"`
}

// normativeCodes are the codes §9.4 allows a denial to carry.
var normativeCodes = map[string]bool{
	"unsupported_language_revision":      true,
	"invalid_capability_id":              true,
	"missing_capability_id":              true,
	"unsupported_wildcard":               true,
	"invalid_params_duplicate_key":       true,
	"invalid_params_number":              true,
	"invalid_params_size":                true,
	"different_namespace":                true,
	"literal_mismatch":                   true,
	"wildcard_requires_trailing_segment": true,
	"empty_bound_denies_class":           true,
	"invalid_params_null":                true,
	"params_missing":                     true,
	"undeclared_param":                   true,
	"not_in_enum":                        true,
	"params_exceed_grant":                true,
	"no_overlap":                         true,
	"absent_source":                      true,
	"capability_not_authorized":          true,
	"unknown_constraint":                 true,
	"invalid_constraint":                 true,
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, c := range normativeCodes {
		_ = c
	}
	if i := strings.IndexByte(msg, ':'); i >= 0 {
		return msg[:i]
	}
	return msg
}

func canonicalGrant(g Grant) string {
	b, _ := json.Marshal(map[string]any{
		"id":          g.ID,
		"params":      g.Params,
		"constraints": sortedCopy(g.Constraints),
	})
	return string(b)
}

// canonicalCode strips the diagnostic suffix (§9.4: everything before the
// first ':' is the normative code).
func canonicalCode(reason string) string {
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// declaredKeys returns the set of parameter keys a grant declares, and whether
// the grant is unconstrained (no params field at all).
func declaredKeys(g Grant) (map[string]bool, bool) {
	if g.Params == nil {
		return nil, true
	}
	keys := make(map[string]bool, len(g.Params))
	for k := range g.Params {
		keys[k] = true
	}
	return keys, false
}

// coveredBySource reports whether the merged grant is covered by one source in
// the composition relation ⊑ defined in §7 rule 2 (source coverage):
//
//   - the source's identifier covers the merged identifier, and
//   - for every parameter key the **source declares**, the merged bound is
//     within the source's bound for that key.
//
// Keys the source does not declare are ignored here: composition authorizes a
// key when *some* source declares it, while layer 7 closure is applied to the
// operation against the effective (merged) grant, which is the only grant a
// verifier ever evaluates (Authorize).  Re-applying each source's closure would
// be a different relation and would deny every merge of differently shaped
// grants (see docs/capability-language-core-design-notes-zh.md §18.3).
func coveredBySource(merged, src Grant) bool {
	if !Entails(Grant{ID: src.ID}, Operation{ID: merged.ID}).Entails {
		return false
	}
	if src.Params == nil {
		return true
	}
	for k, bound := range src.Params {
		got, ok := merged.Params[k]
		if !ok {
			return false
		}
		sub, _ := valueSubset(got, bound)
		if !sub {
			return false
		}
	}
	return true
}

func TestIntersectionProperty(t *testing.T) {
	path := os.Getenv("CLC_PROPERTY_CASES")
	if path == "" {
		path = filepath.Join("..", "..", "capability", "data", "_vectors", "clc-v1", "property-cases.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("property cases not found at %s (set CLC_PROPERTY_CASES): %v", path, err)
	}
	var file propertyFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(file.Cases) == 0 {
		t.Fatalf("%s contains no cases", path)
	}

	orderChecked := 0
	closureChecked := 0
	for _, c := range file.Cases {
		if len(c.Sources) == 0 {
			continue
		}

		merged, err := Intersect(c.Sources...)
		if err != nil {
			code := codeOf(err)
			if !normativeCodes[code] {
				t.Errorf("%s: denial %q is not a normative reason code (§9.4)", c.ID, code)
			}
			continue
		}

		// P11: the merged grant must be covered by every source (⊑, §7 rule 2).
		for i, src := range c.Sources {
			if !coveredBySource(merged, src) {
				t.Errorf("%s (%s): result %s is NOT covered by source %d %s — composition widened",
					c.ID, c.Note, canonicalGrant(merged), i, canonicalGrant(src))
			}
			// No source's constraints may be dropped by the merge.
			for _, con := range src.Constraints {
				if !hasString(merged.Constraints, con) {
					t.Errorf("%s: merged result dropped constraint %q from source %d", c.ID, con, i)
				}
			}
		}

		// Closure belongs to the effective grant only: an operation carrying a
		// parameter key that no source declared must be denied (§9.3 layer 7).
		// Only a *bounded* effective grant closes the key set; an effective grant
		// with no params at all is unconstrained by definition (§6.2), and
		// under rev CLC-1.3 an EMPTY params object is likewise unconstrained
		// (§9.3: {} ≡ absent), so key closure does not apply to it either.
		if merged.ID != "" && merged.Params != nil && len(merged.Params) > 0 {
			probe := Operation{ID: merged.ID, Params: map[string]any{}}
			for k, v := range merged.Params {
				probe.Params[k] = v
			}
			probe.Params["clc_undeclared_probe"] = "x"
			if d := Authorize(merged, probe); canonicalCode(d.Reason) != ErrParamsUndeclared.Error() {
				t.Errorf("%s: operation with an undeclared key resolved to %q, want %q",
					c.ID, d.Reason, ErrParamsUndeclared.Error())
			}
			closureChecked++
		}

		// P11: and the result must not depend on the order of the sources.
		if len(c.Sources) > 1 {
			rev := make([]Grant, len(c.Sources))
			for i, g := range c.Sources {
				rev[len(c.Sources)-1-i] = g
			}
			other, err2 := Intersect(rev...)
			if err2 != nil {
				t.Errorf("%s (%s): reversed order denies (%v) while the original allows", c.ID, c.Note, err2)
			} else if canonicalGrant(other) != canonicalGrant(merged) {
				t.Errorf("%s (%s): result depends on source order: %s vs %s",
					c.ID, c.Note, canonicalGrant(merged), canonicalGrant(other))
			}
			orderChecked++
		}
	}
	t.Logf("P11 property: %d cases, %d order-symmetry checks, %d closure probes",
		len(file.Cases), orderChecked, closureChecked)
}
