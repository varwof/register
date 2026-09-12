// Command vectors-run reads CLC-v1 test vectors and runs them against
// the semantics package.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/varwof/register/semantics"
)

type Vector struct {
	ID               string               `json:"id"`
	Kind             string               `json:"kind"`
	SpecClause       string               `json:"spec_clause"`
	CLCRevision      string               `json:"clc_revision"`
	ConformanceClass string               `json:"conformance_class"`
	Grant            *semantics.Grant     `json:"grant"`
	Request          *semantics.Operation `json:"request"`
	Others           []semantics.Grant    `json:"others"`
	Multi            bool                 `json:"multi,omitempty"` // rev CLC-1.3: §9.3 grant-SET aggregation
	RawParams        string               `json:"raw_params,omitempty"`
	// Principal / Requested are the two constraint-string sets for kind=subset
	// (06-delegation-auth constraint narrowing).
	Principal  []string    `json:"principal,omitempty"`
	Requested  []string    `json:"requested,omitempty"`
	Expect     Expectation `json:"expect"`
	Derivation string      `json:"derivation"`
}

type Expectation struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// Unresolved asserts the decision's §8.4 residual-obligation list
	// (rev CLC-1.2).  nil = not asserted; [] = asserted, must be empty.
	Unresolved []string `json:"unresolved,omitempty"`
	// Result assertions for kind=intersect (§7).  They were declared by the
	// corpus from the start but never read, so the merged params and
	// constraints were unasserted until now.
	ResultParams      map[string]any `json:"result_params,omitempty"`
	ResultConstraints []string       `json:"result_constraints,omitempty"`
}

type Result struct {
	ID           string
	Kind         string
	Expect       string
	Got          string
	ReasonExpect string
	ReasonGot    string
	Note         string
	Pass         bool
}

// canonicalReason returns the stable reason code: everything before the
// first ':' (CLC-v1 §9.4: codes are prefixes; ": <detail>" is diagnostic).
func canonicalReason(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

// checkResult compares the merged grant against the vector's result
// assertions (§7).  An empty string means "matches".
func checkResult(exp Expectation, got semantics.Grant) string {
	if exp.ResultParams != nil {
		want, _ := json.Marshal(exp.ResultParams)
		have, _ := json.Marshal(got.Params)
		if string(want) != string(have) {
			return fmt.Sprintf("result_params want=%s got=%s", want, have)
		}
	}
	if exp.ResultConstraints != nil {
		want := append([]string(nil), exp.ResultConstraints...)
		have := append([]string(nil), got.Constraints...)
		sort.Strings(want)
		sort.Strings(have)
		if strings.Join(want, "\x00") != strings.Join(have, "\x00") {
			return fmt.Sprintf("result_constraints want=%v got=%v", want, have)
		}
	}
	return ""
}

func main() {
	path := os.Getenv("CLC_VECTORS")
	if path == "" {
		// Default relative path: ../capability/data/_vectors/...
		path = "../capability/data/_vectors/clc-v1/vectors.json"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading vectors: %v\n", err)
		os.Exit(1)
	}

	var vectors []Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vectors: %v\n", err)
		os.Exit(1)
	}

	var results []Result
	passCount := 0
	failCount := 0
	reasonFailCount := 0

	for _, v := range vectors {
		r := runVector(v)
		results = append(results, r)
		if !r.Pass {
			if r.ReasonExpect != r.ReasonGot {
				reasonFailCount++
			}
			failCount++
		} else {
			passCount++
		}
	}

	// Print results
	fmt.Printf("%-20s %-8s %-12s %-19s %-22s %-22s %-30s %s\n", "ID", "KIND", "GOT", "EXP-VERDICT", "EXP-REASON", "GOT-REASON", "NOTE", "RESULT")
	fmt.Println(strings.Repeat("-", 120))
	for _, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Printf("%-20s %-8s %-12s %-19s %-22s %-22s %-30s %s\n", r.ID, r.Kind, r.Got, r.Expect, r.ReasonExpect, r.ReasonGot, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d | Reason-fail: %d\n", len(results), passCount, failCount, reasonFailCount)

	if failCount > 0 {
		os.Exit(1)
	}
}

func runVector(v Vector) Result {
	r := Result{ID: v.ID, Kind: v.Kind, ReasonExpect: canonicalReason(v.Expect.Reason)}

	// Input-boundary pre-checks.  Language revision (§12.1) and raw params
	// normalization (§6.2) resolve before any §9.3 layer, so they
	// short-circuit the whole evaluation when they fail.
	if v.Kind == "entail" || v.Kind == "decide" {
		if v.CLCRevision != "" && !semantics.RevisionCompatible(v.CLCRevision) {
			r.Expect = v.Expect.Verdict
			r.Got = "deny"
			r.ReasonGot = canonicalReason(semantics.ErrUnsupportedLangRev.Error())
			r.Pass = r.Got == r.Expect && r.ReasonGot == r.ReasonExpect
			return r
		}
		if v.RawParams != "" {
			if err := semantics.ValidateRawParams(v.RawParams); err != nil {
				r.Expect = v.Expect.Verdict
				r.Got = "deny"
				r.ReasonGot = canonicalReason(err.Error())
				r.Pass = r.Got == r.Expect && r.ReasonGot == r.ReasonExpect
				return r
			}
		}
	}

	verdictOK := false

	switch v.Kind {
	case "syntax":
		r.Expect = v.Expect.Verdict
		if v.Request == nil {
			r.Got = "error"
			return r
		}
		err := semantics.ValidateCapabilityID(v.Request.ID)
		if err != nil {
			r.Got = "invalid"
			r.ReasonGot = canonicalReason(err.Error())
		} else {
			r.Got = "valid"
		}
		verdictOK = (r.Got == v.Expect.Verdict)

	case "subset":
		// 06-delegation-auth constraint narrowing: the agent's requested
		// constraint set must lie inside the principal's boundary.  Errors
		// (malformed / unknown / fail-closed) report "error", never "allow".
		r.Expect = v.Expect.Verdict
		ok, err := semantics.SubsetConstraints(v.Principal, v.Requested)
		if err != nil {
			r.Got = "error"
			r.ReasonGot = canonicalReason(err.Error())
		} else if ok {
			r.Got = "allow"
		} else {
			r.Got = "deny"
		}
		verdictOK = (r.Got == v.Expect.Verdict)

	case "entail":
		r.Expect = v.Expect.Verdict
		if v.Grant == nil || v.Request == nil {
			r.Got = "error"
			return r
		}
		result := semantics.Entails(*v.Grant, *v.Request)
		if result.Entails {
			r.Got = "allow"
		} else {
			r.Got = "deny"
			r.ReasonGot = canonicalReason(result.Reason)
		}
		verdictOK = (r.Got == v.Expect.Verdict)

	case "intersect":
		r.Expect = v.Expect.Verdict
		// A null grant with no `others` is the zero-source intersection
		// (§7 rule 5 -> absent_source), so the grant is only dereferenced
		// when it is actually present.
		var grants []semantics.Grant
		if v.Grant != nil {
			grants = append(grants, *v.Grant)
		}
		grants = append(grants, v.Others...)
		merged, err := semantics.Intersect(grants...)
		if err != nil {
			r.Got = "deny"
			r.ReasonGot = canonicalReason(err.Error())
		} else {
			r.Got = "allow"
		}
		verdictOK = (r.Got == v.Expect.Verdict)
		if err == nil {
			if note := checkResult(v.Expect, merged); note != "" {
				r.Note = note
				verdictOK = false
			}
		}

	case "decide":
		r.Expect = v.Expect.Verdict
		grant := semantics.Grant{}
		if v.Grant != nil {
			grant = *v.Grant
		}
		op := semantics.Operation{}
		if v.Request != nil {
			op = *v.Request
		}

		// Multi-grant §9.3 aggregation (rev CLC-1.3): grant + others form the
		// authorization grant SET; any-allowing grant authorizes (union), and
		// residual obligations union across covering-and-allowing grants.
		if v.Multi {
			grants := []semantics.Grant{grant}
			grants = append(grants, v.Others...)
			result := semantics.AuthorizeSet(grants, op)
			r.Got = result.Verdict
			r.ReasonGot = canonicalReason(result.Reason)
			verdictOK = (r.Got == v.Expect.Verdict)
			if v.Expect.Unresolved != nil {
				want := append([]string(nil), v.Expect.Unresolved...)
				sort.Strings(want)
				if strings.Join(want, "\x00") != strings.Join(result.Unresolved, "\x00") {
					r.Note = fmt.Sprintf("unresolved want=%v got=%v", want, result.Unresolved)
					verdictOK = false
				}
			}
			break
		}

		// Combined vectors: intersect first; capture the intersection reason.
		if len(v.Others) > 0 {
			grants := append([]semantics.Grant{grant}, v.Others...)
			var err error
			grant, err = semantics.Intersect(grants...)
			if err != nil {
				r.Got = "deny"
				r.ReasonGot = canonicalReason(err.Error())
				verdictOK = (r.Got == v.Expect.Verdict)
				break
			}
		}

		result := semantics.Authorize(grant, op)
		r.Got = result.Verdict
		r.ReasonGot = canonicalReason(result.Reason)
		verdictOK = (r.Got == v.Expect.Verdict)
		// §8.4 residual obligations: asserted when the vector declares them
		// (rev CLC-1.2).  Both sides are sorted+deduped before comparison.
		if v.Expect.Unresolved != nil {
			want := append([]string(nil), v.Expect.Unresolved...)
			sort.Strings(want)
			if strings.Join(want, "\x00") != strings.Join(result.Unresolved, "\x00") {
				r.Note = fmt.Sprintf("unresolved want=%v got=%v", want, result.Unresolved)
				verdictOK = false
			}
		}
	}

	// Pass requires BOTH verdict and (canonical) reason to match.
	r.Pass = verdictOK && r.ReasonGot == r.ReasonExpect
	return r
}
