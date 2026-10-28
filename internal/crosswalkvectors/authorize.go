// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/varwof/register/semantics"
)

// AuthorizeVector is one authorize cross-walk case: a carrier's native
// representation is mapped to a CLC grant by a pinned profile, and CLC's own
// authorization function decides one operation against that projected grant.
//
// The mapping lives in the profile, not in this corpus. A vector carries the
// projected grant so the decision is reproducible without re-running the
// carrier; the derivation records where the native representation came from and
// how the profile produced the grant.
//
// This artifact is deliberately distinct from an authorize chain (`ac-NNN`): a
// chain asserts containment per hop and then authorization over the intersection
// within one system, while a cross-walk asserts what a foreign capability model
// means once projected into CLC. Wrapping a single cross-walk case in a
// one-element chain would claim a delegation structure the case does not have.
type AuthorizeVector struct {
	ID         string               `json:"id"`
	Kind       string               `json:"kind"`
	SpecClause string               `json:"spec_clause"`
	Profile    string               `json:"profile"`
	Grant      semantics.Grant      `json:"grant"`
	Operation  semantics.Operation  `json:"operation"`
	Expect     AuthorizeExpectation `json:"expect"`
	// ExecutionChecks are runtime execution-boundary checks the profile leaves
	// to the carrier. They are not carrier policy dimensions and never enter the
	// decision.
	ExecutionChecks []string `json:"execution_checks,omitempty"`
	Derivation      string   `json:"derivation"`
}

// AuthorizeExpectation is the decision a vector asserts.
type AuthorizeExpectation struct {
	Verdict    string   `json:"verdict"`
	Reason     string   `json:"reason,omitempty"`
	Unresolved []string `json:"unresolved,omitempty"`
}

// DefaultAuthorizePath is where the corpus lives relative to the register module.
const DefaultAuthorizePath = "../capability/data/_vectors/clc-d/authorize-crosswalk-vectors.json"

// AuthorizePath returns the corpus location, honouring
// CLC_AUTHORIZE_CROSSWALK_VECTORS.
func AuthorizePath() string {
	if p := os.Getenv("CLC_AUTHORIZE_CROSSWALK_VECTORS"); p != "" {
		return p
	}
	return DefaultAuthorizePath
}

// LoadAuthorize reads and checks the authorize cross-walk corpus.
func LoadAuthorize(path string) ([]AuthorizeVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vectors []AuthorizeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i, v := range vectors {
		if v.ID == "" || v.Profile == "" || v.Grant.ID == "" || v.Operation.ID == "" {
			return nil, fmt.Errorf("%s: vector %d: id, profile, grant.id and operation.id are required", path, i)
		}
		if v.Kind != "authorize-crosswalk" {
			return nil, fmt.Errorf("%s: %s: kind must be authorize-crosswalk, got %q", path, v.ID, v.Kind)
		}
	}
	return vectors, nil
}

// RunAuthorize decides every vector with semantics.Authorize and compares the
// verdict, the canonical reason and the residual obligations.
func RunAuthorize(vectors []AuthorizeVector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runAuthorizeVector(v))
	}
	return out
}

func runAuthorizeVector(v AuthorizeVector) Result {
	r := Result{ID: v.ID, Kind: v.Kind}
	r.Expect = v.Expect.Verdict
	if v.Expect.Reason != "" {
		r.Expect += "/" + canonicalReason(v.Expect.Reason)
	}

	got := semantics.Authorize(v.Grant, v.Operation)
	r.Got = got.Verdict
	if got.Reason != "" {
		r.Got += "/" + canonicalReason(got.Reason)
	}

	// Residual obligations are compared unconditionally: a vector that expects
	// none MUST fail if the implementation invents one, and a vector that
	// expects two MUST fail if only one is reported.
	ok := got.Verdict == v.Expect.Verdict &&
		canonicalReason(got.Reason) == canonicalReason(v.Expect.Reason) &&
		slices.Equal(got.Unresolved, v.Expect.Unresolved)
	if !ok && got.Verdict == v.Expect.Verdict {
		r.Note = fmt.Sprintf("unresolved want=%v got=%v", v.Expect.Unresolved, got.Unresolved)
	}
	r.Pass = ok
	return r
}
