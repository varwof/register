// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command emilia-projection-probe maps EMILIA's evidence-side objects into the
// CLC evidence projection and evaluates them, so the mapping is tested rather
// than asserted.
//
// Inputs are taken from the published drafts (checked 2026-10-17):
//   - EP-AEC-REQUIREMENT-v1 example: draft-schrock-ep-authorization-evidence-chain-08 §4
//   - facts a native verifier would produce: AEB-07 §5.2/§5.6 terms
//   - action shape: draft-schrock-canonical-action-identifier-05 §4.7
//     (tool.call.1); this probe checks CLC's independent material projection
//     and does not claim to parse or map a CAID wire identifier
//
// It prints one line per probe: what was mapped, what CLC decided, and what the
// mapping could not carry (residuals).
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

func digestJSON(v any) string {
	raw, err := semantics.CanonicalJSON(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return "sha-256:" + hex.EncodeToString(sum[:])
}

// digestArtifactSet hashes the target artifacts as a canonical set: members are
// ordered by their JCS bytes, so the order in which a carrier presents them is
// not part of the encoding.  Duplicate members are rejected, not collapsed.
func canonicalArtifactSet(targets []map[string]any) ([]map[string]any, error) {
	type member struct {
		raw []byte
		v   map[string]any
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("artifact set is empty")
	}
	members := make([]member, 0, len(targets))
	for _, t := range targets {
		raw, err := semantics.CanonicalJSON(t)
		if err != nil {
			return nil, err
		}
		members = append(members, member{raw: raw, v: t})
	}
	sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i].raw, members[j].raw) < 0 })
	for i := 1; i < len(members); i++ {
		if bytes.Equal(members[i-1].raw, members[i].raw) {
			return nil, fmt.Errorf("artifact set contains duplicate members")
		}
	}
	// The tuple carries one to.type for the whole set.  A set that mixes types
	// cannot be represented faithfully, and picking targets[0] would make the
	// subject depend on arrival order again.
	for _, m := range members {
		if typ, ok := m.v["type"].(string); !ok || typ == "" {
			return nil, fmt.Errorf("artifact set member has no type")
		}
	}
	for i := 1; i < len(members); i++ {
		if members[i].v["type"] != members[0].v["type"] {
			return nil, fmt.Errorf("artifact set mixes target types %v and %v",
				members[0].v["type"], members[i].v["type"])
		}
	}
	ordered := make([]map[string]any, len(members))
	for i := range members {
		ordered[i] = members[i].v
	}
	return ordered, nil
}

func digestArtifactSet(targets []map[string]any) string {
	ordered, err := canonicalArtifactSet(targets)
	if err != nil {
		panic(err)
	}
	return digestJSON(ordered)
}

type bindingFixture struct {
	RequirementDigest   string           `json:"requirement_digest"`
	Relation            string           `json:"relation"`
	Source              map[string]any   `json:"source"`
	Targets             []map[string]any `json:"targets"`
	Action              map[string]any   `json:"action"`
	Status              map[string]any   `json:"status"`
	Trust               map[string]any   `json:"trust"`
	TrustInputs         map[string]any   `json:"trust_inputs"`
	TrustSnapshotDigest string           `json:"trust_snapshot_digest"`
}

type bindingMutation struct {
	Path  []any `json:"path"`
	Value any   `json:"value"`
}

type bindingFixtureDocument struct {
	Now                string                `json:"now"`
	SourceRequirement  json.RawMessage       `json:"source_requirement"`
	ExpectedSubject    string                `json:"expected_subject"`
	BindingRole        string                `json:"binding_role"`
	MappedRequirement  semantics.Requirement `json:"mapped_requirement"`
	RequirementDigests struct {
		Source    string `json:"source"`
		Projected string `json:"projected"`
	} `json:"requirement_digests"`
	Binding      bindingFixture             `json:"binding"`
	NativeChecks nativeCheckFixture         `json:"native_checks"`
	Mutations    map[string]bindingMutation `json:"mutations"`
	// EvidenceCases are the shared evaluation cases.  Go reads them from the
	// fixture too, so all three probes evaluate the same facts instead of
	// keeping a second copy that can drift.
	EvidenceCases []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		ExpectedGot string `json:"expected_got"`
		Facts       map[string][]struct {
			Subject  string `json:"subject"`
			Verified bool   `json:"verified"`
			AgeSec   int    `json:"age_sec"`
		} `json:"facts"`
	} `json:"evidence_cases"`
}

// nativeCheckFixture pins the explicit native-status-check report cases shared
// by the probes.  The four outcomes are distinct; the last case has no record
// at all and must leave the report incomplete without changing the
// evidence-side satisfaction of an otherwise satisfied requirement.
type nativeCheckFixture struct {
	CheckID               string `json:"check_id"`
	ComponentType         string `json:"component_type"`
	Verifier              string `json:"verifier"`
	VerifierProfileDigest string `json:"verifier_profile_digest"`
	Cases                 []struct {
		Outcome          string `json:"outcome"`
		Reason           string `json:"reason"`
		ExpectedComplete bool   `json:"expected_complete"`
		Note             string `json:"note"`
	} `json:"cases"`
}

// reportDigest renders a fixture object as the profile's typed digest.  The
// profile pins "sha-256:<hex>" because that is the CLC representation; AEC-08
// writes the same algorithm as "sha256:<hex>" and the profile normalizes the
// spelling, without re-hashing, at the boundary.
func reportDigestSet(targets []map[string]any) projection.Digest {
	return projection.Digest(digestArtifactSet(targets))
}

func reportDigest(v any) projection.Digest {
	raw, err := semantics.CanonicalJSON(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return projection.Digest("sha-256:" + hex.EncodeToString(sum[:]))
}

func digestLabel(d *semantics.Digest) string {
	if d == nil {
		return ""
	}
	return d.Alg + ":" + hex.EncodeToString(d.Value)
}

//go:embed testdata/emilia-binding-fixture-v1.json
var bindingFixtureJSON []byte

func loadBindingFixture() bindingFixtureDocument {
	var doc bindingFixtureDocument
	if err := json.Unmarshal(bindingFixtureJSON, &doc); err != nil {
		panic(err)
	}
	return doc
}

func baseBindingFixture() bindingFixture {
	f := loadBindingFixture().Binding
	raw, err := semantics.CanonicalJSON(f.TrustInputs)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	want := "sha-256:" + hex.EncodeToString(sum[:])
	if want != f.TrustSnapshotDigest {
		panic("trust_snapshot_digest does not match trust_inputs")
	}
	return f
}

func fixtureNow() time.Time {
	now, err := time.Parse(time.RFC3339, loadBindingFixture().Now)
	if err != nil {
		panic(err)
	}
	return now
}

func (f bindingFixture) tuple() map[string]any {
	ordered, err := canonicalArtifactSet(f.Targets)
	if err != nil {
		panic(err)
	}
	subjects := make([]string, 0, len(f.Targets))
	issuedAt := []string{f.Source["issued_at"].(string)}
	for _, target := range f.Targets {
		subjects = append(subjects, target["subject"].(string))
		issuedAt = append(issuedAt, target["issued_at"].(string))
	}
	sort.Strings(subjects)
	sort.Strings(issuedAt)
	return map[string]any{
		"requirement_digest": f.RequirementDigest,
		"policy_generation":  f.Source["policy_generation"],
		"from": map[string]any{
			"type":            f.Source["type"],
			"artifact_digest": digestJSON(f.Source),
		},
		"relation": f.Relation,
		"to": map[string]any{
			"type":                ordered[0]["type"],
			"artifact_set_digest": digestJSON(ordered),
		},
		"action_digest":         digestJSON(f.Action),
		"subjects":              subjects,
		"trust":                 f.Trust,
		"trust_snapshot_digest": f.TrustSnapshotDigest,
		"status_digest":         digestJSON(f.Status),
		"status_snapshot":       f.Status,
		"evidence_issued_at":    issuedAt,
	}
}

func bindingSubject(f bindingFixture) string {
	raw, err := semantics.CanonicalJSON(f.tuple())
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mutatedBindingFixture(kind string) bindingFixture {
	doc := loadBindingFixture()
	f := doc.Binding
	mutation, ok := doc.Mutations[kind]
	if !ok {
		panic("unknown binding mutation: " + kind)
	}
	switch kind {
	case "source":
		f.Source[mutation.Path[1].(string)] = mutation.Value
	case "target":
		index := int(mutation.Path[1].(float64))
		f.Targets[index][mutation.Path[2].(string)] = mutation.Value
	case "action":
		f.Action[mutation.Path[1].(string)].(map[string]any)[mutation.Path[2].(string)] = mutation.Value
	case "status":
		f.Status[mutation.Path[1].(string)] = mutation.Value
	default:
		panic("unknown binding mutation: " + kind)
	}
	return f
}

func facts(now time.Time, entities map[string][]struct {
	subject  string
	verified bool
	ago      time.Duration
}) []semantics.EvidenceFact {
	var out []semantics.EvidenceFact
	types := make([]string, 0, len(entities))
	for t := range entities {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		for _, e := range entities[t] {
			out = append(out, semantics.EvidenceFact{
				Type: t, Subject: e.subject, Verified: e.verified, IssuedAt: now.Add(-e.ago),
			})
		}
	}
	return out
}

func evaluate(req semantics.Requirement, fs []semantics.EvidenceFact, now time.Time) string {
	res, err := semantics.EvaluateRequirement(req, fs, semantics.EvidenceContext{Now: now})
	if err != nil {
		return "eval error: " + err.Error()
	}
	sat := res.Satisfaction()
	if sat.Reason == "" {
		return string(sat.Verdict)
	}
	return fmt.Sprintf("%s/%s", sat.Verdict, sat.Reason)
}

func probeRoleMap() map[string]string {
	return map[string]string{
		"ep-human-authorization": "ep-quorum",
		"ep-quorum":              "ep-quorum",
		"policy-permit":          "policy-permit",
	}
}

func main() {
	now := fixtureNow()

	fmt.Println("EMILIA → CLC evidence projection probe")
	fmt.Println("AEC requirement: draft-schrock-ep-authorization-evidence-chain-08 §4")
	fmt.Println()

	fixtureDoc := loadBindingFixture()
	source := []byte(fixtureDoc.SourceRequirement)
	projected, err := projection.Project(source, projection.Options{
		Now:     now,
		RoleMap: probeRoleMap(),
	})
	if err != nil {
		panic(err)
	}
	mapped := *projected.Requirement
	residual := projected.Residuals
	mappedWant, _ := semantics.CanonicalJSON(fixtureDoc.MappedRequirement)
	mappedGot, _ := semantics.CanonicalJSON(mapped)
	if string(mappedGot) != string(mappedWant) {
		panic("mapped requirement differs from shared fixture")
	}
	b, _ := json.MarshalIndent(mapped, "", "  ")
	fmt.Println("1. EP-AEC-REQUIREMENT-v1 → CLC-REQUIREMENT-v1")
	fmt.Println(string(b))
	sourceDigest := digestLabel(projected.SourceRequirementDigest)
	projectedDigest := digestLabel(projected.ProjectedRequirementDigest)
	fmt.Printf("   source requirement digest: %s\n", sourceDigest)
	fmt.Printf("   projected requirement digest: %s\n", projectedDigest)
	if fixtureDoc.RequirementDigests.Source != "" && sourceDigest != fixtureDoc.RequirementDigests.Source {
		panic("source requirement digest differs from shared fixture")
	}
	if fixtureDoc.RequirementDigests.Projected != "" && projectedDigest != fixtureDoc.RequirementDigests.Projected {
		panic("projected requirement digest differs from shared fixture")
	}
	projectionCases := []struct {
		caseID string
		name   string
		want   string
		got    string
	}{
		{"EMI-PROJ-001", "AEC projects to the pinned CLC requirement", "match",
			map[bool]string{true: "match", false: "different"}[string(mappedGot) == string(mappedWant)]},
		{"EMI-PROJ-002", "source requirement digest", fixtureDoc.RequirementDigests.Source, sourceDigest},
		{"EMI-PROJ-003", "projected requirement digest", fixtureDoc.RequirementDigests.Projected, projectedDigest},
	}
	for _, c := range projectionCases {
		status := "PASS"
		if c.got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-46s want=%s got=%s\n", status, c.caseID, c.name, c.want, c.got)
	}
	negativeCases := []struct {
		caseID string
		name   string
		apply  func(map[string]any)
	}{
		{"EMI-PROJ-004", "unknown AEC member rejected", func(doc map[string]any) {
			doc["authorized"] = true
		}},
		{"EMI-PROJ-005", "unpinned role rejected", func(doc map[string]any) {
			doc["freshness_sec"] = map[string]any{"unpinned": 30}
		}},
		{"EMI-PROJ-006", "over-long projected expression rejected", func(doc map[string]any) {
			doc["expression"] = strings.Repeat("a", 520)
		}},
		{"EMI-PROJ-007", "unknown role constraint rejected", func(doc map[string]any) {
			doc["role_constraints"].([]any)[0].(map[string]any)["type"] = "new-constraint"
		}},
		{"EMI-PROJ-008", "presenter-supplied subject rejected", func(doc map[string]any) {
			doc["role_constraints"].([]any)[0].(map[string]any)["subject_id_source"] = "presenter"
		}},
		{"EMI-PROJ-009", "empty binding part rejected", func(doc map[string]any) {
			doc["required_bindings"].([]any)[0].(map[string]any)["from_type"] = ""
		}},
		{"EMI-PROJ-010", "quorum below two rejected", func(doc map[string]any) {
			doc["role_constraints"].([]any)[0].(map[string]any)["threshold"] = 1
		}},
		{"EMI-PROJ-011", "invalid expression grammar rejected", func(doc map[string]any) {
			doc["expression"] = "ep-quorum AND"
		}},
		{"EMI-PROJ-012", "unknown nested role-constraint member rejected", func(doc map[string]any) {
			doc["role_constraints"].([]any)[0].(map[string]any)["note"] = "x"
		}},
		{"EMI-PROJ-013", "negative freshness rejected", func(doc map[string]any) {
			doc["freshness_sec"] = map[string]any{"ep-quorum": -1}
		}},
		{"EMI-PROJ-014", "unknown AEC version rejected", func(doc map[string]any) {
			doc["@version"] = "EP-AEC-REQUIREMENT-v2"
		}},
		{"EMI-PROJ-015", "missing requirement id rejected", func(doc map[string]any) {
			delete(doc, "requirement_id")
		}},
		{"EMI-PROJ-016", "invalid binding identifier rejected", func(doc map[string]any) {
			doc["required_bindings"].([]any)[0].(map[string]any)["from_type"] = "policy permit"
		}},
		{"EMI-PROJ-017", "over-long binding role rejected", func(doc map[string]any) {
			doc["required_bindings"].([]any)[0].(map[string]any)["from_type"] = strings.Repeat("a", 200)
		}},
		{"EMI-PROJ-018", "unknown nested binding member rejected", func(doc map[string]any) {
			doc["required_bindings"].([]any)[0].(map[string]any)["note"] = "x"
		}},
		{"EMI-PROJ-019", "unpinned status_required role rejected", func(doc map[string]any) {
			doc["status_required"] = []any{"unpinned"}
		}},
	}
	for _, c := range negativeCases {
		var doc map[string]any
		if err := json.Unmarshal(source, &doc); err != nil {
			panic(err)
		}
		c.apply(doc)
		raw, err := json.Marshal(doc)
		if err != nil {
			panic(err)
		}
		_, projectErr := projection.Project(raw, projection.Options{
			Now:     now,
			RoleMap: probeRoleMap(),
		})
		got := "rejected"
		if projectErr == nil {
			got = "accepted"
		}
		status := "PASS"
		if got != "rejected" {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-46s want=rejected got=%s\n", status, c.caseID, c.name, got)
	}
	fmt.Println("   residuals:")
	for _, r := range residual {
		fmt.Println("   - " + r)
	}
	fmt.Println("   required native checks:")
	for _, r := range projected.RequiredNativeChecks {
		fmt.Println("   - " + r)
	}
	bindingRole, err := projection.BindingRoleName("policy-permit", "permits", "ep-quorum")
	if err != nil {
		panic(err)
	}
	if bindingRole != fixtureDoc.BindingRole {
		panic("binding role differs from shared fixture")
	}
	bindingFixture := baseBindingFixture()
	// The tuple endpoints must be the relation the requirement names, not a
	// second copy that can drift from it.
	if tupleRole, err := projection.BindingRoleName(
		bindingFixture.Source["type"].(string), bindingFixture.Relation,
		bindingFixture.Targets[0]["type"].(string)); err != nil || tupleRole != bindingRole {
		panic("binding tuple does not match the required binding")
	}
	bindingTuple, _ := semantics.CanonicalJSON(bindingFixture.tuple())
	fmt.Printf("   derived binding role: %s\n", bindingRole)
	fmt.Printf("   relation tuple (JCS): %s\n", bindingTuple)
	fmt.Printf("   derived binding subject: %s\n", bindingSubject(bindingFixture))
	fmt.Println()

	baseBindingSubject := bindingSubject(bindingFixture)
	type caseFact = struct {
		subject  string
		verified bool
		ago      time.Duration
	}
	fmt.Println("2. CLC evaluation over projected facts (§10)")
	for _, c := range fixtureDoc.EvidenceCases {
		entities := make(map[string][]caseFact, len(c.Facts))
		for role, entries := range c.Facts {
			for _, entry := range entries {
				subject := entry.Subject
				if subject == "$binding" {
					subject = baseBindingSubject
				}
				entities[role] = append(entities[role], caseFact{
					subject:  subject,
					verified: entry.Verified,
					ago:      time.Duration(entry.AgeSec) * time.Second,
				})
			}
		}
		got := evaluate(mapped, facts(now, entities), now)
		status := "PASS"
		if got != c.ExpectedGot {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-52s want=%s got=%s\n", status, c.ID, c.Name, c.ExpectedGot, got)
	}
	fmt.Println()

	fmt.Println("3. CLC material action identity (CAID parser/mapping not exercised)")
	def := semantics.ActionTypeDefinition{Type: "tool.call.1", MaterialFields: []string{"tool", "args"}}
	op := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}}
	observedSame := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}, "occurrence_id": "ignored-not-material"}
	observedDiff := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3001, "currency": "CNY"}}
	opID, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, mustProject(def, op))
	if err != nil {
		panic(err)
	}
	for _, c := range []struct {
		caseID string
		name   string
		act    map[string]any
		want   string
	}{
		{"EMI-CAID-001", "CLC projection: extra non-material occurrence_id", observedSame, "MATCH"},
		{"EMI-CAID-002", "CLC projection: material args amount changed", observedDiff, "NOT_EQUIVALENT"},
	} {
		id, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, mustProject(def, c.act))
		got := "error"
		if err == nil {
			got = string(semantics.Match(id, opID))
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-40s want=%s got=%s\n", status, c.caseID, c.name, c.want, got)
	}
	fmt.Println()

	fmt.Println("4. Binding identity derivation and boundary")
	fmt.Println("Fixtures: synthetic AEC-shaped artifacts, not production bytes")
	expectedBindingSubject := fixtureDoc.ExpectedSubject
	reversed := bindingFixture
	reversed.Targets = make([]map[string]any, len(bindingFixture.Targets))
	for i, target := range bindingFixture.Targets {
		reversed.Targets[len(bindingFixture.Targets)-1-i] = target
	}
	duplicated := append(append([]map[string]any{}, bindingFixture.Targets...), bindingFixture.Targets[0])
	_, duplicateErr := canonicalArtifactSet(duplicated)
	mixed := append([]map[string]any{}, bindingFixture.Targets...)
	mixed[1] = map[string]any{}
	for k, v := range bindingFixture.Targets[1] {
		mixed[1][k] = v
	}
	mixed[1]["type"] = "policy-permit"
	_, mixedErr := canonicalArtifactSet(mixed)
	_, emptyErr := canonicalArtifactSet(nil)
	bindingCases := []struct {
		caseID string
		name   string
		want   string
		got    string
	}{
		{
			"EMI-BIND-001",
			"base relation tuple has the pinned subject",
			expectedBindingSubject,
			baseBindingSubject,
		},
		{
			"EMI-BIND-007",
			"artifact set order does not change the relation subject",
			"unchanged",
			map[bool]string{true: "unchanged", false: "different"}[bindingSubject(reversed) == baseBindingSubject],
		},
		{
			"EMI-BIND-008",
			"duplicate artifact member rejected",
			"rejected",
			map[bool]string{true: "rejected", false: "accepted"}[duplicateErr != nil],
		},
		{
			"EMI-BIND-009",
			"mixed target types rejected",
			"rejected",
			map[bool]string{true: "rejected", false: "accepted"}[mixedErr != nil],
		},
		{
			"EMI-BIND-010",
			"empty artifact set rejected",
			"rejected",
			map[bool]string{true: "rejected", false: "accepted"}[emptyErr != nil],
		},
	}
	mutationIDs := map[string]string{
		"source": "EMI-BIND-002",
		"target": "EMI-BIND-003",
		"action": "EMI-BIND-004",
		"status": "EMI-BIND-005",
	}
	for _, mutation := range []string{"source", "target", "action", "status"} {
		bindingCases = append(bindingCases, struct {
			caseID string
			name   string
			want   string
			got    string
		}{
			mutationIDs[mutation],
			mutation + " mutation changes the relation subject",
			"different",
			map[bool]string{true: "different", false: "unchanged"}[bindingSubject(mutatedBindingFixture(mutation)) != baseBindingSubject],
		})
	}
	opaque := evaluate(mapped, facts(now, map[string][]caseFact{
		"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
		"policy-permit": {{"policy", true, 60 * time.Second}},
		bindingRole:     {{"arbitrary-unbound-subject", true, 60 * time.Second}},
	}), now)
	bindingCases = append(bindingCases, struct {
		caseID string
		name   string
		want   string
		got    string
	}{
		"EMI-BIND-006",
		"CLC treats the binding subject as opaque",
		"opaque-subject-accepted",
		map[bool]string{true: "opaque-subject-accepted", false: "unexpectedly-rejected"}[strings.SplitN(opaque, "/", 2)[0] == "SATISFIED"],
	})
	for _, c := range bindingCases {
		status := "PASS"
		if c.got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-55s want=%s got=%s\n", status, c.caseID, c.name, c.want, c.got)
	}
	fmt.Println()

	// Section 5 is informational, not a new set of case IDs: the cross-language
	// probes consume the same fixture and must keep reporting the same EMILIA
	// cases.  Each line asserts the completeness rule by panicking on a
	// mismatch, so a wrong report fails the probe's exit status.
	fmt.Println("5. Native status-check results (explicit, never inferred from an empty list)")
	native := fixtureDoc.NativeChecks
	binding := baseBindingFixture()
	attribution := func() projection.NativeCheckResult {
		return projection.NativeCheckResult{
			CheckID:               native.CheckID,
			ComponentType:         native.ComponentType,
			EvidenceDigest:        reportDigestSet(binding.Targets),
			Verifier:              native.Verifier,
			VerifierProfileDigest: projection.Digest(native.VerifierProfileDigest),
			TrustSnapshotDigest:   reportDigest(binding.Trust),
			StatusSnapshotDigest:  reportDigest(binding.Status),
			VerificationTime:      now,
			FreshnessDecision:     &projection.FreshnessDecision{Verdict: projection.FreshnessFresh},
		}
	}
	eligibleFacts := facts(now, map[string][]struct {
		subject  string
		verified bool
		ago      time.Duration
	}{
		"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
		"policy-permit": {{"policy", true, 60 * time.Second}},
		bindingRole:     {{baseBindingSubject, true, 60 * time.Second}},
	})
	for _, c := range native.Cases {
		var results []projection.NativeCheckResult
		if c.Outcome != "" {
			result := attribution()
			result.Outcome = projection.NativeCheckOutcome(c.Outcome)
			result.Reason = c.Reason
			results = append(results, result)
		}
		// The last case intentionally supplies eligible facts and no result:
		// the evidence-side verdict stays SATISFIED while the report is not
		// complete, which is exactly the boundary this section documents.
		suppliedFacts := []semantics.EvidenceFact(nil)
		if c.Outcome == "" {
			suppliedFacts = eligibleFacts
		}
		rep, err := projection.Project(source, projection.Options{
			Now:     now,
			RoleMap: probeRoleMap(),
			Facts:   suppliedFacts,
			// The EMILIA profile supplies the expected component inventory;
			// otherwise completeness would only check that a result with the
			// right check id exists, not which artifact it came from.
			NativeCheckExpectations: []projection.NativeCheckExpectation{{
				CheckID:        native.CheckID,
				ComponentType:  native.ComponentType,
				EvidenceDigest: reportDigestSet(binding.Targets),
			}},
			NativeCheckResults: results,
		})
		if err != nil {
			panic(err)
		}
		if rep.NativeChecksComplete != c.ExpectedComplete {
			panic(fmt.Sprintf(
				"native check %q: complete=%v, fixture expects %v",
				c.Outcome, rep.NativeChecksComplete, c.ExpectedComplete))
		}
		outcome := c.Outcome
		if outcome == "" {
			outcome = "(no result)"
		}
		satisfaction := "not-evaluated"
		if rep.Satisfaction != nil {
			sat := rep.Satisfaction.Satisfaction()
			satisfaction = string(sat.Verdict)
			if sat.Reason != "" {
				satisfaction += "/" + sat.Reason
			}
		}
		fmt.Printf("   %-14s complete=%-5v satisfaction=%-14s reason=%s\n",
			outcome, rep.NativeChecksComplete, satisfaction, c.Reason)
	}
}

func mustProject(def semantics.ActionTypeDefinition, action map[string]any) map[string]any {
	p, err := semantics.MaterialProjection(def, action)
	if err != nil {
		panic(err)
	}
	return p
}
