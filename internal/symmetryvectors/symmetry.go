// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package symmetryvectors runs the authorization/evidence symmetry corpus: each
// vector carries both sides of one action — the grant and operation the
// authorization relation decides, and the action observed after execution — so
// the pair is asserted together rather than in two unrelated suites.
//
// The properties it pins are the ones that differ between the two sides:
// authority is set-bounded, evidence identity is exact; an undeclared operation
// parameter denies while an undeclared observed field carries no identity; and a
// residual decision (allow_unresolved) still has an exact action identity.
package symmetryvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// DefaultPath is where the symmetry corpus lives relative to the register module.
const DefaultPath = "../capability/data/_vectors/clc-v1/symmetry-vectors.json"

// Path returns the corpus location, honouring CLC_SYMMETRY_VECTORS.
func Path() string {
	if p := os.Getenv("CLC_SYMMETRY_VECTORS"); p != "" {
		return p
	}
	return DefaultPath
}

// ActionType is the material projection the evidence side applies.
type ActionType struct {
	Name     string   `json:"name"`
	Material []string `json:"material"`
}

// Authorization carries the grant/operation pair and its expected decision.
type Authorization struct {
	// Chain selects the fused chain check (§13.11) instead of the multi-grant
	// aggregation of §9: grants are ordered root first.
	Chain     bool                `json:"chain,omitempty"`
	Grants    []semantics.Grant   `json:"grants"`
	Operation semantics.Operation `json:"operation"`
	Verdict   string              `json:"verdict"`
	Reason    string              `json:"reason,omitempty"`
	// UnresolvedContains lists residual constraints the decision must carry
	// (§8.4): the union across covering grants and chain hops must not drop one.
	UnresolvedContains []string `json:"unresolved_contains,omitempty"`
}

// Vector is one authorization/evidence pair.
type Vector struct {
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	SpecClause    string         `json:"spec_clause"`
	Type          ActionType     `json:"type"`
	Suite         string         `json:"suite"`
	Authorization Authorization  `json:"authorization"`
	Observed      map[string]any `json:"observed,omitempty"`
	// ObservedType and ObservedSuite let a case compare across a boundary the
	// language refuses to compare (different type or suite).
	ObservedType  string `json:"observed_type,omitempty"`
	ObservedSuite string `json:"observed_suite,omitempty"`
	// NoEvidence asserts that a refused action produced no evidence at all.
	NoEvidence bool `json:"no_evidence,omitempty"`
	// Evidence, when present, is the evidence-side obligation carried by the
	// same action: the constraint evaluated over facts supplied by the caller.
	Evidence *EvidenceBlock `json:"evidence,omitempty"`
	Expect   struct {
		Match string `json:"match"`
	} `json:"expect"`
}

// EvidenceBlock is one evidence constraint and the facts it is evaluated over.
type EvidenceBlock struct {
	Constraint string `json:"constraint,omitempty"`
	// Requirement, when present, is evaluated as a CLC-REQUIREMENT-v1 object
	// over the same facts instead of a single constraint.
	Requirement json.RawMessage `json:"requirement,omitempty"`
	Context     struct {
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
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// Error, when set, expects the constraint to be refused before evaluation
	// (for example an authorization-side constraint offered as evidence).
	Error string `json:"error,omitempty"`
}

// Result is one vector's outcome.
type Result struct {
	ID   string
	Pass bool
	Note string
}

// Load reads a symmetry corpus file.
func Load(path string) ([]Vector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vs []Vector
	if err := json.Unmarshal(data, &vs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return vs, nil
}

// ResolvePath finds the corpus next to the package or via the module-relative
// default, mirroring the other corpora.
func ResolvePath() (string, error) {
	if p := Path(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	alt := filepath.Join("..", "..", "..", "capability", "data", "_vectors", "clc-v1", "symmetry-vectors.json")
	if _, err := os.Stat(alt); err == nil {
		return alt, nil
	}
	return "", fmt.Errorf("symmetry corpus unavailable (set CLC_SYMMETRY_VECTORS)")
}

// Run evaluates each vector's authorization decision and, where an observation
// exists, the identity match between the authorized operation and that
// observation.
func Run(vectors []Vector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runOne(v))
	}
	return out
}

func runOne(v Vector) Result {
	r := Result{ID: v.ID}
	var dec semantics.Decision
	if v.Authorization.Chain {
		dec = semantics.AuthorizeWithChain(v.Authorization.Grants, v.Authorization.Operation)
	} else {
		dec = semantics.AuthorizeSet(v.Authorization.Grants, v.Authorization.Operation)
	}
	if dec.Verdict != v.Authorization.Verdict {
		r.Note = fmt.Sprintf("authorization: want %s, got %s (%s)",
			v.Authorization.Verdict, dec.Verdict, dec.Reason)
		return r
	}
	if v.Authorization.Reason != "" && dec.Reason != v.Authorization.Reason {
		r.Note = fmt.Sprintf("authorization reason: want %s, got %s",
			v.Authorization.Reason, dec.Reason)
		return r
	}
	for _, want := range v.Authorization.UnresolvedContains {
		if !containsString(dec.Unresolved, want) {
			r.Note = fmt.Sprintf("authorization unresolved: want %q in %v", want, dec.Unresolved)
			return r
		}
	}

	got, note := match(v)
	if got != v.Expect.Match {
		r.Note = fmt.Sprintf("match: want %s, got %s%s", v.Expect.Match, got, note)
		return r
	}
	if v.Evidence != nil {
		verdict, reason, err := evalEvidence(v.Evidence)
		if err != nil {
			if v.Evidence.Error != "" && strings.HasPrefix(err.Error(), v.Evidence.Error) {
				r.Pass = true
				return r
			}
			r.Note = fmt.Sprintf("evidence: %v", err)
			return r
		}
		if v.Evidence.Error != "" {
			r.Note = fmt.Sprintf("evidence: want error %s, got verdict %s", v.Evidence.Error, verdict)
			return r
		}
		if verdict != v.Evidence.Verdict {
			r.Note = fmt.Sprintf("evidence: want %s, got %s (%s)",
				v.Evidence.Verdict, verdict, reason)
			return r
		}
		if v.Evidence.Reason != "" && reason != v.Evidence.Reason {
			r.Note = fmt.Sprintf("evidence reason: want %s, got %s",
				v.Evidence.Reason, reason)
			return r
		}
	}
	r.Pass = true
	return r
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func evalEvidence(b *EvidenceBlock) (string, string, error) {
	ctx := semantics.EvidenceContext{Initiator: b.Context.Initiator, Executor: b.Context.Executor}
	if b.Context.Now != "" {
		now, err := time.Parse(time.RFC3339, b.Context.Now)
		if err != nil {
			return "", "", fmt.Errorf("context.now: %w", err)
		}
		ctx.Now = now.UTC()
	}
	facts := make([]semantics.EvidenceFact, 0, len(b.Facts))
	for _, f := range b.Facts {
		fact := semantics.EvidenceFact{Type: f.Type, Subject: f.Subject, Verified: f.Verified}
		if f.IssuedAt != "" {
			t, err := time.Parse(time.RFC3339, f.IssuedAt)
			if err != nil {
				return "", "", fmt.Errorf("issued_at: %w", err)
			}
			fact.IssuedAt = t.UTC()
		}
		facts = append(facts, fact)
	}
	if len(b.Requirement) > 0 {
		req, err := semantics.ParseRequirement(b.Requirement)
		if err != nil {
			return "", "", err
		}
		res, err := semantics.EvaluateRequirement(req, facts, ctx)
		if err != nil {
			return "", "", err
		}
		sat := res.Satisfaction()
		return string(sat.Verdict), sat.Reason, nil
	}
	ev, err := semantics.EvaluateEvidenceConstraint(b.Constraint, facts, ctx)
	return string(ev.Verdict), ev.Reason, err
}

func match(v Vector) (string, string) {
	if v.NoEvidence {
		if v.Observed != nil {
			return "EVIDENCE_PRESENT", ""
		}
		return "NO_EVIDENCE", ""
	}
	def := semantics.ActionTypeDefinition{Type: v.Type.Name, MaterialFields: v.Type.Material}
	if v.ObservedType != "" && v.ObservedType != def.Type {
		return string(semantics.MatchIndeterminate), ""
	}
	if v.ObservedSuite != "" && v.ObservedSuite != v.Suite {
		return string(semantics.MatchIndeterminate), ""
	}
	opMat, err := semantics.MaterialProjection(def, v.Authorization.Operation.Params)
	if err != nil {
		return "action_not_matchable", ": " + err.Error()
	}
	obsMat, err := semantics.MaterialProjection(def, v.Observed)
	if err != nil {
		return "action_not_matchable", ""
	}
	opID, err := semantics.ComputeActionID(def, semantics.ActionIdSuite(v.Suite), opMat)
	if err != nil {
		return "action_not_matchable", ": " + err.Error()
	}
	obsID, err := semantics.ComputeActionID(def, semantics.ActionIdSuite(v.Suite), obsMat)
	if err != nil {
		return "action_not_matchable", ": " + err.Error()
	}
	return string(semantics.Match(obsID, opID)), ""
}
