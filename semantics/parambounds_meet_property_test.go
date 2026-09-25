// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBoundMeetProperty is the executable form of the §6.6 meet invariant
// (rev CLC-1.15):
//
//	for every case (sources sharing one identifier and one param_bounds key)
//	and every operation o in the shared sample:
//	  * Intersect(sources) MUST NOT raise, and a refusal MUST carry a
//	    normative reason code (fail closed), and
//	  * when Intersect succeeds with grant G:
//	      Entails(G, o)  ==>  Entails(S, o) for EVERY source S
//	    — every successful meet authorizes only what each source authorizes
//	    on its own (the law the CLC-1.14 filtered-enum reduction violated),
//	    and the reversed fold MUST succeed with the identical canonical
//	    result (order independence on success, §7 rules 2/6).
//
// The case list lives in the capability repository
// (data/_vectors/clc-v1/param-bounds-meet-property-cases.json); override with
// CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES.

type meetPropertyFile struct {
	Ops   []Operation `json:"ops"`
	Cases []struct {
		ID      string  `json:"id"`
		Sources []Grant `json:"sources"`
		Note    string  `json:"note"`
	} `json:"cases"`
}

// meetNormativeCodes are the §9.2 codes an Intersect refusal may carry.
var meetNormativeCodes = map[string]bool{
	"unsupported_language_revision":      true,
	"invalid_capability_id":              true,
	"missing_capability_id":              true,
	"unsupported_wildcard":               true,
	"invalid_params_duplicate_key":       true,
	"invalid_params_number":              true,
	"invalid_params_size":                true,
	"invalid_params_binding":             true,
	"params_cardinality":                 true,
	"params_out_of_range":                true,
	"params_not_multiple":                true,
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
}

func canonicalMeetGrant(g Grant) string {
	b, _ := json.Marshal(map[string]any{
		"id":           g.ID,
		"params":       g.Params,
		"param_bounds": g.ParamBounds,
		"constraints":  sortedCopy(g.Constraints),
	})
	return string(b)
}

func TestBoundMeetProperty(t *testing.T) {
	path := os.Getenv("CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES")
	if path == "" {
		path = filepath.Join("..", "..", "capability", "data", "_vectors", "clc-v1", "param-bounds-meet-property-cases.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("meet property cases not found at %s (set CLC_PARAM_BOUNDS_MEET_PROPERTY_CASES): %v", path, err)
	}
	var file meetPropertyFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(file.Cases) == 0 || len(file.Ops) == 0 {
		t.Fatalf("%s carries no cases or ops", path)
	}

	meets := 0
	orderChecked := 0
	opChecks := 0
	for _, c := range file.Cases {
		if len(c.Sources) == 0 {
			continue
		}

		merged, err := Intersect(c.Sources...)
		if err != nil {
			code := codeOf(err)
			if !meetNormativeCodes[code] {
				t.Errorf("%s: denial %q is not a normative reason code (§9.2)", c.ID, code)
			}
			continue
		}
		meets++

		// The meet invariant: G authorizes o only when EVERY source does.
		for _, op := range file.Ops {
			opChecks++
			if !Entails(merged, op).Entails {
				continue
			}
			for i, src := range c.Sources {
				if !Entails(src, op).Entails {
					t.Errorf("%s (%s): meet authorizes op %+v but source %d %+v does not (merged=%s)",
						c.ID, c.Note, op, i, src, canonicalMeetGrant(merged))
					break
				}
			}
		}

		// Order independence on success.
		rev := make([]Grant, len(c.Sources))
		for i, g := range c.Sources {
			rev[len(c.Sources)-1-i] = g
		}
		other, err2 := Intersect(rev...)
		if err2 != nil {
			t.Errorf("%s (%s): reversed order denies (%v) while the original allows", c.ID, c.Note, err2)
		} else if canonicalMeetGrant(other) != canonicalMeetGrant(merged) {
			t.Errorf("%s (%s): result depends on source order: %s vs %s",
				c.ID, c.Note, canonicalMeetGrant(merged), canonicalMeetGrant(other))
		}
		orderChecked++
	}
	t.Logf("meet-property: %d cases, %d successful meets, %d order-symmetry checks, %d op-checks",
		len(file.Cases), meets, orderChecked, opChecks)
}
