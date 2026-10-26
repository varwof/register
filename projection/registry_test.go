// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"testing"
	"time"

	"github.com/varwof/register/projection"
)

const nativeRequirement = `{
  "@version": "CLC-REQUIREMENT-v1",
  "requirement_id": "wire-release-evidence@7",
  "expression": "human-authorization AND policy-permit",
  "constraints": [
    {"role": "human-authorization", "constraint": "varwof/evidence-v1:quorum:distinct:2"}
  ]
}`

func registeredIDs() map[string]bool {
	ids := make(map[string]bool)
	for _, p := range projection.List() {
		ids[p.ID()] = true
	}
	return ids
}

// The built-in projectors are part of the language surface: CLC's own shape is
// always available, and the foreign adapters register alongside it.
func TestBuiltinsAreRegistered(t *testing.T) {
	ids := registeredIDs()
	for _, want := range []string{"clc/requirement-v1", "emilia/ep-aec-requirement-v1"} {
		if !ids[want] {
			t.Errorf("projector %q is not registered; have %v", want, ids)
		}
	}
}

func TestFindSelectsByDeclaredVersion(t *testing.T) {
	if p := projection.Find([]byte(nativeRequirement)); p == nil || p.ID() != "clc/requirement-v1" {
		t.Fatalf("native document matched %v, want clc/requirement-v1", p)
	}
	if p := projection.Find([]byte(`{"@version":"EP-AEC-REQUIREMENT-v1"}`)); p == nil || p.ID() != "emilia/ep-aec-requirement-v1" {
		t.Fatalf("foreign document matched %v, want emilia/ep-aec-requirement-v1", p)
	}
	if p := projection.Find([]byte(`{"@version":"unknown/v9"}`)); p != nil {
		t.Fatalf("unknown document matched %q, want no projector", p.ID())
	}
}

// An unmatched document is an error, never an implicit allow.
func TestNormalizeUnknownFormatFailsClosed(t *testing.T) {
	if _, err := projection.Normalize([]byte(`{"@version":"unknown/v9"}`), projection.Context{}); err == nil {
		t.Fatal("Normalize accepted an unknown format")
	}
}

// Project keeps the native path lossless: the document was already in the
// target shape, so it yields the requirement and no residuals.
func TestRegisterRejectsTypedNilAndDuplicates(t *testing.T) {
	var nilP *registryTestProjector
	// A typed-nil interface must not be registered.
	projection.Register(nilP)
	p := &registryTestProjector{id: "test/registry-projector"}
	projection.Register(p)
	projection.Register(p)
	projection.Register(&registryTestProjector{id: "test/registry-projector"})
	count := 0
	for _, got := range projection.List() {
		if got.ID() == "test/registry-projector" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate projector count = %d, want 1", count)
	}
}

type registryTestProjector struct{ id string }

func (p *registryTestProjector) ID() string        { return p.id }
func (p *registryTestProjector) Match([]byte) bool { return false }
func (p *registryTestProjector) Project([]byte, projection.Context) (projection.ProjectedView, error) {
	return projection.ProjectedView{}, nil
}

func TestProjectNativeRequirement(t *testing.T) {
	now := time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC)
	rep, err := projection.Project([]byte(nativeRequirement), projection.Options{Now: now})
	if err != nil {
		t.Fatalf("project native requirement: %v", err)
	}
	if rep.ProjectorID != "clc/requirement-v1" {
		t.Errorf("projector = %q", rep.ProjectorID)
	}
	if rep.Requirement == nil {
		t.Fatal("no requirement projected")
	}
	if rep.Requirement.ID != "wire-release-evidence@7" {
		t.Errorf("requirement id = %q", rep.Requirement.ID)
	}
	if len(rep.Residuals) != 0 {
		t.Errorf("residuals = %v, want none for a native document", rep.Residuals)
	}
	if rep.Satisfaction != nil {
		t.Errorf("satisfaction = %+v, want nil when no facts were supplied", rep.Satisfaction)
	}
	if rep.Meta["project_ctx_now_utc"] != now.Format(time.RFC3339) {
		t.Errorf("projection clock = %q, want %q", rep.Meta["project_ctx_now_utc"], now.Format(time.RFC3339))
	}
}

func TestProjectAECRejectsUnknownMembers(t *testing.T) {
	doc := []byte(`{
		"@version":"EP-AEC-REQUIREMENT-v1",
		"requirement_id":"aec@1",
		"expression":"x",
		"authorized":true,
		"role_constraints":[{"type":"distinct-subject-quorum","component_type":"carrier","threshold":2,"extra":1}],
		"required_bindings":[{"from_type":"a","relation":"issued","to_type":"b","foo":"bar"}]
	}`)
	if _, err := projection.Project(doc, projection.Options{}); err == nil {
		t.Fatal("projection accepted unknown AEC members")
	}
}

// The native path reports the same dual digests as a foreign projection.  For
// an already-canonical CLC requirement the source and projected objects agree,
// and both are independently recomputable.
func TestProjectNativeRequirementReportsDigests(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	rep, err := projection.Project([]byte(nativeRequirement), projection.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SourceRequirementDigest == nil || rep.ProjectedRequirementDigest == nil {
		t.Fatal("native projection did not report both digests")
	}
	wantProjected, err := rep.Requirement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ProjectedRequirementDigest.Equal(wantProjected) {
		t.Fatalf("projected digest = %+v, want %+v", *rep.ProjectedRequirementDigest, wantProjected)
	}
	wantSource := recomputeSourceDigest(t, nativeRequirement)
	if !rep.SourceRequirementDigest.Equal(wantSource) {
		t.Fatalf("source digest = %+v, want %+v", *rep.SourceRequirementDigest, wantSource)
	}
	if len(rep.NativeCheckResults) != 0 {
		t.Fatalf("native requirement unexpectedly has native check results: %+v", rep.NativeCheckResults)
	}
}
