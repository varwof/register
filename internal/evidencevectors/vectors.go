// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package evidencevectors loads and runs the CLC-E evidence-side conformance
// corpus.  The corpus lives beside the CLC-A vectors in the capability module
// (capability/data/_vectors/clc-v1/evidence-vectors.json) so both sides of the
// language are pinned by machine-readable data rather than by prose.
//
// §12 makes a conformance class claimable only when an implementation *and*
// vectors exist; this package is the runner half of that for CLC-E.
package evidencevectors

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// Vector is one evidence-side conformance case.
type Vector struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"` // constraint | requirement | requirement_raw
	SpecClause string `json:"spec_clause"`
	Constraint string `json:"constraint"`
	// Requirement is the parsed-form requirement object (kind=requirement).
	Requirement json.RawMessage `json:"requirement"`
	// Raw is the literal bytes to parse (kind=requirement_raw).
	Raw string `json:"raw"`
	// ActionType / Suite / Action describe an action-id vector (kind=action_id).
	ActionType struct {
		Type           string   `json:"type"`
		MaterialFields []string `json:"material_fields"`
	} `json:"action_type"`
	Suite    string         `json:"suite"`
	Action   map[string]any `json:"action"`
	Observed string         `json:"observed"`
	Evidence string         `json:"evidence"`
	Context  struct {
		Now       string `json:"now"`
		Initiator string `json:"initiator"`
		Executor  string `json:"executor"`
	} `json:"context"`
	Facts []struct {
		Type     string `json:"type"`
		Subject  string `json:"subject"`
		IssuedAt string `json:"issued_at"`
		Verified bool   `json:"verified"`
	} `json:"facts"`
	Expect struct {
		Verdict      string   `json:"verdict"`
		Reason       string   `json:"reason"`
		Expression   *bool    `json:"expression"`
		MissingRoles []string `json:"missing_roles"`
		Error        string   `json:"error"`
		// ActionId asserts the exact identifier string (kind=action_id).
		ActionId string `json:"action_id"`
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
	// Missing is the observed missing-role list (requirement vectors).
	Missing []string
	// Expression is the observed expression result; nil when not applicable.
	Expression *bool
	Pass       bool
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

// DefaultPath is where the corpus lives relative to the register module.
const DefaultPath = "../capability/data/_vectors/clc-v1/evidence-vectors.json"

// Path returns the corpus location, honouring CLC_EVIDENCE_VECTORS.
func Path() string {
	if p := os.Getenv("CLC_EVIDENCE_VECTORS"); p != "" {
		return p
	}
	return DefaultPath
}

// Run evaluates every vector and reports the outcomes.
func Run(vectors []Vector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runVector(v))
	}
	return out
}

func runVector(v Vector) Result {
	r := Result{ID: v.ID, Kind: v.Kind}

	ctx, err := v.context()
	if err != nil {
		r.Expect, r.Got, r.Note = v.expectLabel(), "error", err.Error()
		return r
	}
	facts := v.facts()

	switch v.Kind {
	case "constraint":
		evaluation, err := semantics.EvaluateEvidenceConstraint(v.Constraint, facts, ctx)
		if err != nil {
			r.Got, r.Note = err.Error(), ""
		} else {
			r.Got = string(evaluation.Verdict)
			r.Note = evaluation.Reason
			if v.Expect.Reason != "" {
				r.Got += "/" + evaluation.Reason
			}
		}
	case "requirement":
		req, err := semantics.ParseRequirement(v.Requirement)
		if err != nil {
			r.Got, r.Note = err.Error(), ""
			break
		}
		result, err := semantics.EvaluateRequirement(req, facts, ctx)
		if err != nil {
			r.Got, r.Note = err.Error(), ""
			break
		}
		r.Got = string(result.Verdict)
		expr := result.Expression
		r.Expression = &expr
		r.Missing = append([]string(nil), result.MissingRoles...)
		r.Note = fmt.Sprintf("expression=%v missing=%v", result.Expression, result.MissingRoles)
	case "action_id":
		id, err := semantics.ComputeActionID(
			semantics.ActionTypeDefinition{Type: v.ActionType.Type, MaterialFields: v.ActionType.MaterialFields},
			semantics.ActionIdSuite(v.Suite), v.Action)
		if err != nil {
			r.Got = err.Error()
		} else {
			r.Got = id.String()
		}
	case "match":
		observed, errObserved := semantics.ParseActionId(v.Observed)
		evidence, errEvidence := semantics.ParseActionId(v.Evidence)
		switch {
		case errObserved != nil:
			r.Got = errObserved.Error()
		case errEvidence != nil:
			r.Got = errEvidence.Error()
		default:
			r.Got = string(semantics.Match(observed, evidence))
		}
	case "requirement_raw":
		_, err := semantics.ParseRequirement([]byte(v.Raw))
		if err != nil {
			r.Got = err.Error()
		} else {
			r.Got = "parsed"
		}
	default:
		r.Got = "unknown kind"
	}

	r.Expect = v.expectLabel()
	r.Pass = resultMatches(v, r)
	return r
}

// resultMatches compares the observed outcome with the vector's expectation.
// Verdicts are compared exactly; reasons and error codes are compared as stable
// prefixes, the same way the CLC-A runner treats them.
func resultMatches(v Vector, r Result) bool {
	if v.Expect.Error != "" {
		return strings.Contains(r.Got, v.Expect.Error)
	}
	if v.Expect.ActionId != "" {
		return r.Got == v.Expect.ActionId
	}
	if !strings.HasPrefix(r.Got, v.Expect.Verdict) {
		return false
	}
	if v.Expect.Reason != "" && !strings.Contains(r.Got, v.Expect.Reason) {
		return false
	}
	if v.Expect.Expression != nil {
		if r.Expression == nil || *r.Expression != *v.Expect.Expression {
			return false
		}
	}
	if v.Expect.MissingRoles != nil {
		got := append([]string(nil), r.Missing...)
		want := append([]string(nil), v.Expect.MissingRoles...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			return false
		}
	}
	return true
}

func (v Vector) expectLabel() string {
	if v.Expect.ActionId != "" {
		return v.Expect.ActionId
	}
	if v.Expect.Error != "" {
		return "error:" + v.Expect.Error
	}
	if v.Expect.Reason != "" {
		return v.Expect.Verdict + "/" + v.Expect.Reason
	}
	return v.Expect.Verdict
}

func (v Vector) context() (semantics.EvidenceContext, error) {
	ctx := semantics.EvidenceContext{Initiator: v.Context.Initiator, Executor: v.Context.Executor}
	if v.Context.Now == "" {
		return ctx, nil
	}
	now, err := time.Parse(time.RFC3339, v.Context.Now)
	if err != nil {
		return ctx, fmt.Errorf("context.now: %w", err)
	}
	ctx.Now = now.UTC()
	return ctx, nil
}

func (v Vector) facts() []semantics.EvidenceFact {
	out := make([]semantics.EvidenceFact, 0, len(v.Facts))
	for _, f := range v.Facts {
		fact := semantics.EvidenceFact{Type: f.Type, Subject: f.Subject, Verified: f.Verified}
		if f.IssuedAt != "" {
			if t, err := time.Parse(time.RFC3339, f.IssuedAt); err == nil {
				fact.IssuedAt = t.UTC()
			}
		}
		out = append(out, fact)
	}
	return out
}
