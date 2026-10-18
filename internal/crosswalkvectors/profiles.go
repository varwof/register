// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Profile declarations discharge core §13.8.1 obligations 6 and 7 (rev
// CLC-1.18) for every carrier profile the two cross-walk corpora use:
//
//   - obligation 6 — a profile that concludes a chain result from adjacent
//     pairs alone MUST declare its transitivity basis (definition-derived,
//     mechanically-checkable, asserted — with domain and procedure where the
//     basis is the middle one).  A profile that iterates the per-pair relation
//     and composes by Intersect makes no such claim and MUST NOT declare one.
//   - obligation 7 — a carrier field that is conjunctive over a chain MUST be
//     routed to the constraint union or enforced by the carrier, and MUST NOT
//     be reported as a containment result.
//
// The file is data, not prose: the checks below are the executable half of the
// rule, and the corpus-coverage check keeps it honest (one declaration per
// profile used, none for a profile that does not exist).

// DefaultDeclarationsPath is where the declarations live relative to the
// register module.
const DefaultDeclarationsPath = "../capability/data/_vectors/clc-v1/profile-declarations.json"

// DeclarationsPath returns the declarations location, honouring
// CLC_PROFILE_DECLARATIONS.
func DeclarationsPath() string {
	if p := os.Getenv("CLC_PROFILE_DECLARATIONS"); p != "" {
		return p
	}
	return DefaultDeclarationsPath
}

// ChainCheck is the obligation-6 half of a declaration.
type ChainCheck struct {
	IteratesHops         bool   `json:"iterates_hops"`
	ReliesOnTransitivity bool   `json:"relies_on_transitivity"`
	Basis                string `json:"basis,omitempty"`
	Domain               string `json:"domain,omitempty"`
	Procedure            string `json:"procedure,omitempty"`
	Argument             string `json:"argument,omitempty"`
	Note                 string `json:"note,omitempty"`
}

// UnionAxis is the obligation-7 half of a declaration.
type UnionAxis struct {
	Fields   []string `json:"fields"`
	RoutedTo string   `json:"routed_to"`
}

// ProfileDeclaration is one carrier profile's discharge of §13.8.1 obligations
// 6 and 7.
type ProfileDeclaration struct {
	Profile      string     `json:"profile"`
	Illustrative bool       `json:"illustrative,omitempty"`
	Corpora      []string   `json:"corpora,omitempty"`
	ChainCheck   ChainCheck `json:"chain_check"`
	UnionAxis    UnionAxis  `json:"union_axis"`
}

// NegativeCase pairs a deliberately non-conforming declaration with the reason
// code the check must produce for it.
type NegativeCase struct {
	ID          string             `json:"id"`
	Want        string             `json:"want"`
	Declaration ProfileDeclaration `json:"declaration"`
}

// Declarations is the whole file.
type Declarations struct {
	Schema        string               `json:"schema"`
	SpecClause    string               `json:"spec_clause"`
	Declarations  []ProfileDeclaration `json:"declarations"`
	Examples      []ProfileDeclaration `json:"examples"`
	NegativeCases []NegativeCase       `json:"negative_cases"`
}

// LoadDeclarations reads the profile-declaration file.
func LoadDeclarations(path string) (*Declarations, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Declarations
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if d.Schema != "clc-profile-declarations-v1" {
		return nil, fmt.Errorf("%s: unknown schema %q", path, d.Schema)
	}
	return &d, nil
}

// checkBasis is the obligation-6 decision procedure.  It returns one reason
// code per violated rule, so a caller can assert the code rather than a boolean.
func checkBasis(c ChainCheck) []string {
	var issues []string
	switch c.Basis {
	case "":
		issues = append(issues, "basis-missing")
	case "definition-derived":
		if c.Domain == "" || c.Argument == "" {
			issues = append(issues, "domain-or-argument-missing")
		}
	case "mechanically-checkable":
		if c.Domain == "" || c.Procedure == "" {
			issues = append(issues, "domain-or-procedure-missing")
		}
	case "asserted":
		// nothing further is owed: the basis is the carrier's statement
	default:
		issues = append(issues, "unknown-basis")
	}
	return issues
}

// CheckDeclaration returns the reason codes a declaration violates (obligations
// 6 and 7).  An empty result is a conforming declaration.
func CheckDeclaration(d ProfileDeclaration) []string {
	var issues []string
	if d.Profile == "" {
		issues = append(issues, "missing-profile")
	}
	if d.ChainCheck.ReliesOnTransitivity {
		if !d.ChainCheck.IteratesHops {
			issues = append(issues, "transitivity-without-iteration")
		}
		issues = append(issues, checkBasis(d.ChainCheck)...)
	} else if d.ChainCheck.Basis != "" || d.ChainCheck.Domain != "" ||
		d.ChainCheck.Procedure != "" || d.ChainCheck.Argument != "" {
		// §13.8.1 obligation 6: a profile that makes no transitivity claim
		// MUST NOT claim a basis.
		issues = append(issues, "basis-without-claim")
	}

	switch d.UnionAxis.RoutedTo {
	case "constraint-union", "carrier-enforced":
		if len(d.UnionAxis.Fields) == 0 {
			issues = append(issues, "union-axis-fields-mismatch")
		}
	case "not-applicable":
		if len(d.UnionAxis.Fields) != 0 {
			issues = append(issues, "union-axis-fields-mismatch")
		}
	default:
		// A union axis reported as contained/narrowed is exactly the failure
		// obligation 7 closes.
		issues = append(issues, "union-axis-misrouted")
	}
	return issues
}

// ProfilesInCorpora returns every distinct profile named by the two cross-walk
// corpora, mapped to the corpus that named it.  Entries without a profile (the
// reverse-mapping crossing cases) are skipped: they project a CLC decision
// outward and name no carrier.
func ProfilesInCorpora(paths ...string) (map[string][]string, error) {
	found := map[string][]string{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var entries []struct {
			Profile string `json:"profile"`
		}
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		for _, e := range entries {
			if e.Profile == "" {
				continue
			}
			if !contains(found[e.Profile], filepath.Base(p)) {
				found[e.Profile] = append(found[e.Profile], filepath.Base(p))
			}
		}
	}
	return found, nil
}

// CheckCoverage returns the reason codes for the corpus-coverage half: every
// profile the corpora use must have exactly one declaration, and a declaration
// must not exist for a profile the corpora do not use.
func CheckCoverage(d *Declarations, used map[string][]string) map[string][]string {
	issues := map[string][]string{}
	seen := map[string]int{}
	for _, dec := range d.Declarations {
		seen[dec.Profile]++
		if _, ok := used[dec.Profile]; !ok {
			issues[dec.Profile] = append(issues[dec.Profile], "orphan-declaration")
		}
	}
	for p := range used {
		switch seen[p] {
		case 1:
		case 0:
			issues[p] = append(issues[p], "missing-declaration")
		default:
			issues[p] = append(issues[p], "duplicate-declaration")
		}
	}
	return issues
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
