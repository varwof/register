// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/semantics"
)

// ContainVector is one CLC-D containment cross-walk case: a native
// representation from another ecosystem is mapped into a CLC grant by a pinned
// profile on *each* side (parent boundary and child request), and the
// containment relation decides the pair.  It is the delegation-attenuation
// analogue of the CLC-A cross-walk corpus: the carrier stays the carrier's,
// the mapping is the profile's, and only the CLC verdict/reason is asserted.
type ContainVector struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	SpecClause   string          `json:"spec_clause"`
	Profile      string          `json:"profile"`
	ParentSource json.RawMessage `json:"parent_source"`
	ChildSource  json.RawMessage `json:"child_source"`
	// OutOfScope names the carrier dimensions this profile declares out of
	// scope (core §13.8.1 obligation 3): fields the mapped grant cannot carry.
	// The relation must never see them — a profile that maps a declared
	// out-of-scope dimension into a grant is a defect, not a containment
	// result.
	OutOfScope []string `json:"out_of_scope,omitempty"`
	Expect     struct {
		Contains bool   `json:"contains"`
		Reason   string `json:"reason,omitempty"`
	} `json:"expect"`
	Derivation string `json:"derivation"`
}

// DefaultContainPath is where the CLC-D cross-walk corpus lives relative to the
// register module.
const DefaultContainPath = "../capability/data/_vectors/clc-d/containment-crosswalk-vectors.json"

// ContainPath returns the CLC-D cross-walk corpus location, honouring
// CLC_D_CROSSWALK_VECTORS.
func ContainPath() string {
	if p := os.Getenv("CLC_D_CROSSWALK_VECTORS"); p != "" {
		return p
	}
	return DefaultContainPath
}

// LoadContain reads a CLC-D cross-walk corpus file.
func LoadContain(path string) ([]ContainVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vectors []ContainVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, err
	}
	return vectors, nil
}

// RunContain evaluates every CLC-D cross-walk vector.
func RunContain(vectors []ContainVector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runContainVector(v))
	}
	return out
}

func runContainVector(v ContainVector) Result {
	r := Result{ID: v.ID, Kind: v.Kind}
	if v.Expect.Contains {
		r.Expect = "contains"
	} else {
		r.Expect = "not_contains"
		if v.Expect.Reason != "" {
			r.Expect += "/" + canonicalReason(v.Expect.Reason)
		}
	}

	parent, err := mapSingleGrant(v.Profile, v.ParentSource)
	if err != nil {
		r.Got, r.Note = "map error", "parent: "+err.Error()
		return r
	}
	child, err := mapSingleGrant(v.Profile, v.ChildSource)
	if err != nil {
		r.Got, r.Note = "map error", "child: "+err.Error()
		return r
	}
	// Obligation 3 (core §13.8.1): a dimension the profile declares out of
	// scope must never arrive inside a mapped grant.  If the profile mapped it
	// into a parameter (or dropped it silently), the relation would be asked to
	// compare something it cannot see — this is the fail-closed rule, and a
	// violation here is a profile defect, not a containment verdict.
	if leak := declaredOutOfScopeLeak(v.OutOfScope, parent, child); len(leak) > 0 {
		r.Got, r.Note = "map error", "out_of_scope dimension leaked into mapped grant: "+strings.Join(leak, ", ")
		return r
	}

	res := semantics.Contains(parent, child)
	if res.Contains {
		r.Got = "contains"
	} else {
		r.Got = "not_contains"
		if res.Reason != "" {
			r.Got += "/" + canonicalReason(res.Reason)
		}
	}
	r.Note = fmt.Sprintf("P=%s C=%s", parent.ID, child.ID)
	r.Pass = res.Contains == v.Expect.Contains
	if r.Pass && !res.Contains && canonicalReason(v.Expect.Reason) != "" {
		r.Pass = canonicalReason(res.Reason) == canonicalReason(v.Expect.Reason)
	}
	return r
}

// declaredOutOfScopeLeak reports declared out-of-scope dimensions that still
// appear inside a mapped grant's parameters or identifier.  A dimension cannot
// be both "not in the mapped grant" and "compared" — if it is present, the
// profile silently dropped or smuggled it, which obligation 3 forbids.
func declaredOutOfScopeLeak(declared []string, grants ...semantics.Grant) []string {
	var leak []string
	for _, name := range declared {
		for _, g := range grants {
			if _, ok := g.Params[name]; ok {
				leak = append(leak, name)
				break
			}
		}
	}
	return leak
}

// mapSingleGrant applies a cross-walk profile and requires the native
// representation to map to exactly one grant — containment is a relation over
// single grants, so a multi-capability source is a profile-level error, not a
// silent first-element pick.
func mapSingleGrant(profile string, source json.RawMessage) (semantics.Grant, error) {
	grants, err := MapProfile(profile, source)
	if err != nil {
		return semantics.Grant{}, err
	}
	if len(grants) != 1 {
		return semantics.Grant{}, fmt.Errorf("profile %q must map to exactly one grant, got %d", profile, len(grants))
	}
	return grants[0], nil
}
