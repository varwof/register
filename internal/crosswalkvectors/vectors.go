// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package crosswalkvectors runs the cross-walk corpus: native capability
// representations from other ecosystems, mapped into CLC grants by a pinned
// profile, and decided by the same CLC core.
//
// The point of the corpus is the genericity claim in Appendix A — CLC is not
// shaped around AIC or EMILIA, and a third party can map its own representation
// into CLC without changing CLC.  Each vector names its profile; the mapping
// itself lives here as the profile implementation (a third party would write its
// own), and the vector asserts only the resulting CLC decision.
package crosswalkvectors

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/varwof/register/semantics"
)

// Vector is one cross-walk case.
type Vector struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	SpecClause string              `json:"spec_clause"`
	Profile    string              `json:"profile"`
	Source     json.RawMessage     `json:"source"`
	Operation  semantics.Operation `json:"operation"`
	// Grants is the CLC grant set for kind=crossing (reverse mapping) vectors.
	Grants []semantics.Grant `json:"grants"`
	Expect struct {
		Verdict    string   `json:"verdict"`
		Reason     string   `json:"reason,omitempty"`
		Unresolved []string `json:"unresolved,omitempty"`
		// Crossing asserts the reverse-mapping fields (kind=crossing).
		Crossing *struct {
			AuthorizationDecision       bool     `json:"authorization_decision"`
			AuthoritySemanticsPreserved bool     `json:"authority_semantics_preserved"`
			RequestedCapabilityDigest   string   `json:"requested_capability_digest,omitempty"`
			UnresolvedCount             *int     `json:"unresolved_count,omitempty"`
			UnsuppliedCount             *int     `json:"unsupplied_count,omitempty"`
			UnsuppliedMustInclude       []string `json:"unsupplied_must_include,omitempty"`
		} `json:"crossing,omitempty"`
	} `json:"expect"`
	Derivation string `json:"derivation"`
}

// Result is one vector's outcome.
type Result struct {
	ID     string
	Kind   string
	Expect string
	Got    string
	Note   string
	Pass   bool
}

// DefaultPath is where the corpus lives relative to the register module.
const DefaultPath = "../capability/data/_vectors/clc-v1/crosswalk-vectors.json"

// Path returns the corpus location, honouring CLC_CROSSWALK_VECTORS.
func Path() string {
	if p := os.Getenv("CLC_CROSSWALK_VECTORS"); p != "" {
		return p
	}
	return DefaultPath
}

// Load reads a corpus file.
func Load(path string) ([]Vector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vectors []Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, err
	}
	return vectors, nil
}

// Run evaluates every vector.
func Run(vectors []Vector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runVector(v))
	}
	return out
}

func runVector(v Vector) Result {
	r := Result{ID: v.ID, Kind: v.Kind, Expect: v.expectLabel()}

	if v.Kind == "crossing" {
		projection, err := MapCrossing(v.Grants, v.Operation)
		if err != nil {
			r.Got, r.Note = "map error", err.Error()
			return r
		}
		r.Got = projection.Verdict
		if projection.Reason != "" {
			r.Got += "/" + projection.Reason
		}
		r.Note = fmt.Sprintf("cap=%s record=%s unsupplied=%d",
			short(projection.RequestedCapabilityDigest), short(projection.CLCRecordDigest), len(projection.Unsupplied))
		r.Pass = crossingMatches(v, projection)
		return r
	}

	grants, err := MapProfile(v.Profile, v.Source)
	if err != nil {
		r.Got, r.Note = "map error", err.Error()
		return r
	}
	decision := semantics.AuthorizeSet(grants, v.Operation)
	r.Got = decision.Verdict
	if decision.Reason != "" {
		r.Got += "/" + canonicalReason(decision.Reason)
	}
	if len(decision.Unresolved) > 0 {
		r.Note = fmt.Sprintf("unresolved=%v", decision.Unresolved)
	}
	r.Pass = verdictMatches(v, decision)
	return r
}

func verdictMatches(v Vector, d semantics.Decision) bool {
	if d.Verdict != v.Expect.Verdict {
		return false
	}
	if want := canonicalReason(v.Expect.Reason); want != "" && canonicalReason(d.Reason) != want {
		return false
	}
	if v.Expect.Unresolved != nil {
		want, _ := json.Marshal(v.Expect.Unresolved)
		have, _ := json.Marshal(d.Unresolved)
		if string(want) != string(have) {
			return false
		}
	}
	return true
}

func (v Vector) expectLabel() string {
	if v.Expect.Reason != "" {
		return v.Expect.Verdict + "/" + canonicalReason(v.Expect.Reason)
	}
	return v.Expect.Verdict
}

func canonicalReason(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

// MapProfile applies one pinned cross-walk profile: native representation in,
// CLC grant set out.  Profiles are named "<source>->clc-v1"; an unknown profile
// is an error, never a guess.
func MapProfile(profile string, source json.RawMessage) ([]semantics.Grant, error) {
	switch profile {
	case "oauth-rar->clc-v1":
		// RFC 9396 §2: {"type": <capability scheme>, "actions": [...], "params": {...}}
		var rar struct {
			Type    string         `json:"type"`
			Actions []string       `json:"actions"`
			Params  map[string]any `json:"params"`
		}
		if err := json.Unmarshal(source, &rar); err != nil {
			return nil, err
		}
		if rar.Type == "" || len(rar.Actions) == 0 {
			return nil, fmt.Errorf("rar: type and at least one action are required")
		}
		grants := make([]semantics.Grant, 0, len(rar.Actions))
		for _, action := range rar.Actions {
			grants = append(grants, semantics.Grant{ID: rar.Type + ":" + action, Params: rar.Params})
		}
		return grants, nil

	case "aic-jwt-da->clc-v1":
		// AIC-JWT §5: capability[] = {id, params?, constraints?[]}
		var da struct {
			Capabilities []struct {
				ID          string         `json:"id"`
				Params      map[string]any `json:"params,omitempty"`
				Constraints []string       `json:"constraints,omitempty"`
			} `json:"capabilities"`
		}
		if err := json.Unmarshal(source, &da); err != nil {
			return nil, err
		}
		grants := make([]semantics.Grant, 0, len(da.Capabilities))
		for _, c := range da.Capabilities {
			grants = append(grants, semantics.Grant{ID: c.ID, Params: c.Params, Constraints: c.Constraints})
		}
		return grants, nil

	case "emilia-aeg->clc-v1":
		// Action Evidence Graph: a node/edge names the capability class it is about.
		var aeg struct {
			CapabilityClass string `json:"capability_class"`
		}
		if err := json.Unmarshal(source, &aeg); err != nil {
			return nil, err
		}
		if aeg.CapabilityClass == "" {
			return nil, fmt.Errorf("aeg: capability_class required")
		}
		return []semantics.Grant{{ID: aeg.CapabilityClass}}, nil

	case "ucan->clc-v1":
		// UCAN capability {with, can}: "with" names the scheme, "can" the action.
		var u struct {
			With string `json:"with"`
			Can  string `json:"can"`
		}
		if err := json.Unmarshal(source, &u); err != nil {
			return nil, err
		}
		if u.With == "" || u.Can == "" {
			return nil, fmt.Errorf("ucan: with and can are required")
		}
		return []semantics.Grant{{ID: u.With + ":" + u.Can}}, nil

	case "delegation-chain->clc-v1":
		// Each link narrows: the effective grant is the §7 intersection.
		var chain struct {
			Links []semantics.Grant `json:"links"`
		}
		if err := json.Unmarshal(source, &chain); err != nil {
			return nil, err
		}
		if len(chain.Links) == 0 {
			return nil, fmt.Errorf("delegation chain: at least one link required")
		}
		merged, err := semantics.Intersect(chain.Links...)
		if err != nil {
			return nil, err
		}
		return []semantics.Grant{merged}, nil

	default:
		return nil, fmt.Errorf("unknown cross-walk profile %q", profile)
	}
}

// crossingMatches compares a projection with the vector's assertions.
func crossingMatches(v Vector, p CrossingProjection) bool {
	if p.Verdict != v.Expect.Verdict {
		return false
	}
	if want := canonicalReason(v.Expect.Reason); want != "" && p.Reason != want {
		return false
	}
	if v.Expect.Crossing == nil {
		return true
	}
	c := v.Expect.Crossing
	if c.AuthorizationDecision != p.AuthorizationDecision {
		return false
	}
	if c.AuthoritySemanticsPreserved != p.AuthoritySemanticsPreserved {
		return false
	}
	if c.RequestedCapabilityDigest != "" && c.RequestedCapabilityDigest != p.RequestedCapabilityDigest {
		return false
	}
	if c.UnresolvedCount != nil && *c.UnresolvedCount != len(p.Unresolved) {
		return false
	}
	if c.UnsuppliedCount != nil && *c.UnsuppliedCount != len(p.Unsupplied) {
		return false
	}
	for _, m := range c.UnsuppliedMustInclude {
		found := false
		for _, u := range p.Unsupplied {
			if u.Member == m {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 18 {
		return s
	}
	return s[:18] + "…"
}
