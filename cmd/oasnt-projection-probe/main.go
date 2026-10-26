// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command oasnt-projection-probe projects an OASNT approval token
// (draft-thallapelly-oasnt-02) onto the CLC evidence projection.
//
// OASNT is an independent evidence source: a human approval token bound to a
// flat canonical action (adg), a disclosure digest (dsp), an optional request
// fingerprint (rqf), a single-use nonce (jti), and a device integrity result
// (int).  The probe shows that the profile-neutral native-check mechanism
// (expectation inventory, closed outcomes, assessment, Fact lineage) serves
// OASNT exactly as it serves EMILIA, without carrier-specific branches.
//
// The fixture is synthetic OASNT-shaped evidence, not production JWT bytes.
// Claims follow draft-thallapelly-oasnt-02 §5.3, the canonical action §6.2, and
// the verification steps §7.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

// canonicalAction is the §6.2 string: escape(type) "|" escape(k)=escape(v) &...
func canonicalAction(typ string, params map[string]string) string {
	esc := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch r {
			case '\\', '|', '=', '&':
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(esc(typ))
	b.WriteString("|")
	for i, k := range keys {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(esc(k))
		b.WriteString("=")
		b.WriteString(esc(params[k]))
	}
	return b.String()
}

// adg is the base64url (unpadded) SHA-256 of the canonical action.
func adg(typ string, params map[string]string) string {
	sum := sha256.Sum256([]byte(canonicalAction(typ, params)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type action struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

type inventoryEntry struct {
	CheckID        string            `json:"check_id"`
	ComponentType  string            `json:"component_type"`
	EvidenceDigest projection.Digest `json:"evidence_digest"`
}

type nativeCase struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Results     map[string]string `json:"results"`
	Reasons     map[string]string `json:"reasons"`
	ActionMatch bool              `json:"action_match"`
	Want        string            `json:"want"`
}

type fixture struct {
	Version string `json:"@version"`
	Note    string `json:"note"`
	Now     string `json:"now"`
	Token   struct {
		Sub    string            `json:"sub"`
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
		Iat    int64             `json:"iat"`
		Exp    int64             `json:"exp"`
		Int    string            `json:"int"`
		Jti    string            `json:"jti"`
		Dsp    string            `json:"dsp"`
		Rqf    string            `json:"rqf"`
		Asl    string            `json:"asl"`
	} `json:"token"`
	Presented struct {
		Match    action `json:"match"`
		Mismatch action `json:"mismatch"`
	} `json:"presented"`
	Adg                   string            `json:"adg"`
	ArtifactDigest        projection.Digest `json:"artifact_digest"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	ActionMapping         struct {
		MaterialProfileID    string            `json:"material_profile_id"`
		MappingProfileID     string            `json:"mapping_profile_id"`
		MappingProfileDigest projection.Digest `json:"mapping_profile_digest"`
		CLCActionType        string            `json:"clc_action_type"`
		CLCMaterialFields    []string          `json:"clc_material_fields"`
		CLCTool              string            `json:"clc_tool"`
		CLCArgs              map[string]any    `json:"clc_args"`
	} `json:"action_mapping"`
	CheckInventory []inventoryEntry `json:"check_inventory"`
	Residuals      []string         `json:"residuals"`
	Cases          []nativeCase     `json:"cases"`
}

//go:embed testdata/oasnt-approval-fixture-v1.json
var fixtureJSON []byte

func loadFixture() fixture {
	var f fixture
	if err := json.Unmarshal(fixtureJSON, &f); err != nil {
		panic(err)
	}
	return f
}

func (f fixture) now() time.Time {
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		panic(err)
	}
	return now
}

const requirementDoc = `{
  "@version": "CLC-REQUIREMENT-v1",
  "requirement_id": "oasnt-approval@1",
  "expression": "human-authorization",
  "constraints": [
    {"role": "human-authorization", "constraint": "varwof/evidence-v1:freshness:sec:300"}
  ]
}`

func parseRequirement() semantics.Requirement {
	req, err := semantics.ParseRequirement([]byte(requirementDoc))
	if err != nil {
		panic(err)
	}
	return req
}

// checkOutcome returns the outcome for one inventory entry, or "missing" when
// the profile reported no result for it.  It never infers a result.
func checkOutcome(c nativeCase, checkID string) string {
	if outcome, ok := c.Results[checkID]; ok && outcome != "" {
		return outcome
	}
	return "missing"
}

// nativeResults builds the explicit results for the components the case
// reports.  Every result carries the profile attribution the report requires;
// a missing entry stays missing rather than becoming a synthetic outcome.
func nativeResults(f fixture, c nativeCase, now time.Time) []projection.NativeCheckResult {
	results := make([]projection.NativeCheckResult, 0, len(c.Results))
	for _, check := range f.CheckInventory {
		outcome, ok := c.Results[check.CheckID]
		if !ok || outcome == "" {
			continue
		}
		result := projection.NativeCheckResult{
			CheckID:               check.CheckID,
			ComponentType:         check.ComponentType,
			EvidenceDigest:        check.EvidenceDigest,
			Outcome:               projection.NativeCheckOutcome(outcome),
			Reason:                c.Reasons[check.CheckID],
			Verifier:              f.Verifier,
			VerifierProfileDigest: f.VerifierProfileDigest,
			TrustSnapshotDigest:   f.TrustSnapshotDigest,
			StatusSnapshotDigest:  f.StatusSnapshotDigest,
			VerificationTime:      now,
			FreshnessDecision:     &projection.FreshnessDecision{Verdict: projection.FreshnessFresh},
		}
		if outcome == string(projection.NativeCheckFailed) {
			result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessStale}
		}
		// A checked component declares which status snapshot it used, so a
		// deployer can detect a rollback or fork across reports.
		if outcome == string(projection.NativeCheckSuccess) || outcome == string(projection.NativeCheckFailed) {
			result.StatusSnapshotSource = "aeb-status"
			result.StatusSnapshotGeneration = 42
		}
		results = append(results, result)
	}
	return results
}

// caseActionMatches recomputes adg from the action the case presents.  The
// token's adg is never used as the source of the comparison.
func caseActionMatches(f fixture, c nativeCase) bool {
	presented := f.Presented.Match
	if !c.ActionMatch {
		presented = f.Presented.Mismatch
	}
	return adg(presented.Type, presented.Params) == f.Adg
}

// eligible reports whether the profile may emit a Fact: the presented action
// matches, the declared inventory is fully reported, and every required gate
// passed.  jti consumption is deliberately absent: it belongs to the
// enforcement point.
func eligible(f fixture, c nativeCase, report *projection.Report) bool {
	if !c.ActionMatch || report.NativeCheckAssessment == nil || !report.NativeCheckAssessment.Complete {
		return false
	}
	for _, check := range f.CheckInventory {
		if checkOutcome(c, check.CheckID) != string(projection.NativeCheckSuccess) {
			return false
		}
	}
	return true
}

func fact(f fixture, issuedAt time.Time) semantics.EvidenceFact {
	return semantics.EvidenceFact{
		Type:     "human-authorization",
		Subject:  f.Token.Sub,
		Verified: true,
		IssuedAt: issuedAt,
	}
}

// buildReport assembles the profile-neutral report for one case.
func buildReport(f fixture, c nativeCase, req semantics.Requirement, now time.Time, issuedAt time.Time, withFact bool) *projection.Report {
	def := semantics.ActionTypeDefinition{
		Type:           f.ActionMapping.CLCActionType,
		MaterialFields: f.ActionMapping.CLCMaterialFields,
	}
	clcAction := map[string]any{
		"tool": f.ActionMapping.CLCTool,
		"args": f.ActionMapping.CLCArgs,
	}
	presented := f.Presented.Match
	if !c.ActionMatch {
		presented = f.Presented.Mismatch
	}
	// The pinned mapping profile is declared for the approved action.  A
	// mismatch therefore carries the native digest only: claiming a CLC
	// ActionId for an action the profile never mapped would invent a relation.
	clcID := ""
	if c.ActionMatch {
		id, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, clcAction)
		if err != nil {
			panic(err)
		}
		clcID = id.String()
	}
	observation := &projection.ProjectedObservation{
		NativeActionDigest:   adg(presented.Type, presented.Params),
		CLCActionID:          clcID,
		ActionType:           f.ActionMapping.CLCActionType,
		MaterialFields:       f.ActionMapping.CLCMaterialFields,
		MaterialProfileID:    f.ActionMapping.MaterialProfileID,
		MappingProfileDigest: f.ActionMapping.MappingProfileDigest,
	}

	expectations := make([]projection.NativeCheckExpectation, 0, len(f.CheckInventory))
	for _, check := range f.CheckInventory {
		expectations = append(expectations, projection.NativeCheckExpectation{
			CheckID:        check.CheckID,
			ComponentType:  check.ComponentType,
			EvidenceDigest: check.EvidenceDigest,
		})
	}

	// A lineage record may only name checks that actually produced a result over
	// this artifact; a missing result must not be papered over by the record.
	gating := make([]string, 0, len(f.CheckInventory))
	for _, check := range f.CheckInventory {
		if outcome := c.Results[check.CheckID]; outcome != "" {
			gating = append(gating, check.CheckID)
		}
	}

	facts := []semantics.EvidenceFact{}
	var records []projection.ProjectedEvidenceRecord
	if withFact {
		eligibleFact := fact(f, issuedAt)
		facts = append(facts, eligibleFact)
		records = append(records, projection.ProjectedEvidenceRecord{
			ArtifactDigest: f.ArtifactDigest,
			ObservationID:  observation.NativeActionDigest,
			Fact:           &eligibleFact,
			NativeCheckIDs: gating,
		})
	} else {
		records = append(records, projection.ProjectedEvidenceRecord{
			ArtifactDigest: f.ArtifactDigest,
			ObservationID:  observation.NativeActionDigest,
			NativeCheckIDs: gating,
		})
	}

	profile := &projection.Profile{
		ID:                  "oasnt/ep-approval-token-v1",
		StatusModel:         projection.StatusRequired,
		ReasonNamespace:     "oasnt",
		RequiredChecks:      []string{"oasnt:token-validity", "oasnt:device-integrity"},
		Expectations:        expectations,
		ActionMappingDigest: f.ActionMapping.MappingProfileDigest,
		ProfileDigest:       f.ProfileDigest,
	}
	if err := profile.Seal(); err != nil {
		panic(err)
	}

	report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
		ProjectorID:             "oasnt/ep-approval-token-v1",
		SourceFormat:            "OASNT-02/approval-token",
		Meta:                    map[string]string{"mapped_at_utc": now.UTC().Format(time.RFC3339)},
		Requirement:             &req,
		RequiredNativeChecks:    profile.RequiredChecks,
		NativeCheckExpectations: expectations,
		NativeCheckResults:      nativeResults(f, c, now),
		Facts:                   facts,
		Observation:             observation,
		EvidenceRecords:         records,
		Profile:                 profile,
		Verifier: &projection.VerifierIdentity{
			Principal:             f.Verifier,
			VerifierProfileDigest: f.VerifierProfileDigest,
		},
		Residuals: f.Residuals,
		Now:       now,
	})
	if err != nil {
		panic(err)
	}
	return report
}

func verdict(report *projection.Report) string {
	if report.Satisfaction == nil {
		return "not-evaluated"
	}
	sat := report.Satisfaction.Satisfaction()
	if sat.Reason == "" {
		return string(sat.Verdict)
	}
	return fmt.Sprintf("%s/%s", sat.Verdict, sat.Reason)
}

func main() {
	f := loadFixture()
	now := f.now()
	req := parseRequirement()

	fmt.Println("OASNT approval → CLC evidence projection")
	fmt.Println("Fields: draft-thallapelly-oasnt-02 §5.3/§6.2/§7 (checked 2026-10-25)")
	fmt.Println("fixture: synthetic OASNT-shaped evidence, not production JWT bytes")
	fmt.Printf("subject: %s\n", f.Token.Sub)
	fmt.Printf("canonical action: %s\n", canonicalAction(f.Token.Type, f.Token.Params))
	fmt.Printf("adg: %s\n", f.Adg)
	fmt.Println()

	fmt.Println("1. Action binding (adg) against the presented action")
	if !caseActionMatches(f, nativeCase{ActionMatch: true}) {
		panic("fixture does not match: the matching presentation must reproduce adg")
	}
	for _, c := range []struct {
		caseID string
		name   string
		params map[string]string
		want   string
	}{
		{"OAS-ADG-001", "same action", f.Presented.Match.Params, "MATCH"},
		{"OAS-ADG-002", "amount 3001", f.Presented.Mismatch.Params, "NOT_EQUIVALENT"},
		{"OAS-ADG-003", "extra parameter added", map[string]string{
			"amount": "3000", "currency": "CNY", "memo": "x",
		}, "NOT_EQUIVALENT"},
	} {
		got := "NOT_EQUIVALENT"
		if adg(f.Presented.Match.Type, c.params) == f.Adg {
			got = "MATCH"
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-28s want=%s got=%s\n", status, c.caseID, c.name, c.want, got)
	}
	fmt.Println()

	fmt.Println("2. Explicit native-check results and the fact-lineage report")
	for _, c := range f.Cases {
		if got := caseActionMatches(f, c); got != c.ActionMatch {
			panic(fmt.Sprintf("fixture case %s: action match=%v, recomputation says %v", c.ID, c.ActionMatch, got))
		}
		probe := buildReport(f, c, req, now, time.Unix(f.Token.Iat, 0).UTC(), false)
		eligibleFact := eligible(f, c, probe)
		report := buildReport(f, c, req, now, time.Unix(f.Token.Iat, 0).UTC(), eligibleFact)
		got := fmt.Sprintf("validity=%s,integrity=%s,action=%s,complete=%t,eligible=%t",
			checkOutcome(c, "oasnt:token-validity"),
			checkOutcome(c, "oasnt:device-integrity"),
			map[bool]string{true: "MATCH", false: "MISMATCH"}[c.ActionMatch],
			report.NativeChecksComplete,
			eligibleFact,
		)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		detail := "req=" + verdict(report)
		if !c.ActionMatch {
			detail += " reason=oasnt:action-mismatch"
		}
		if report.NativeCheckAssessment != nil && len(report.NativeCheckAssessment.MissingExpectations) > 0 {
			detail += fmt.Sprintf(" missing=%d", len(report.NativeCheckAssessment.MissingExpectations))
		}
		fmt.Printf("%s %s %-44s %s want=%s got=%s\n", status, c.ID, c.Name, detail, c.Want, got)
	}
	fmt.Println()

	fmt.Println("3. Approval as a CLC fact (§10 requirement over one role)")
	clean := nativeCase{Results: map[string]string{
		"oasnt:token-validity":   string(projection.NativeCheckSuccess),
		"oasnt:device-integrity": string(projection.NativeCheckSuccess),
	}, ActionMatch: true}
	compromised := nativeCase{Results: map[string]string{
		"oasnt:token-validity":   string(projection.NativeCheckSuccess),
		"oasnt:device-integrity": string(projection.NativeCheckFailed),
	}, Reasons: map[string]string{"oasnt:device-integrity": "oasnt:int-compromised"}, ActionMatch: true}
	for _, c := range []struct {
		caseID   string
		name     string
		spec     nativeCase
		issuedAt time.Time
		want     string
	}{
		{"OAS-FACT-001", "int=clean, approved 30s ago", clean, now.Add(-30 * time.Second), "SATISFIED"},
		{"OAS-FACT-002", "int=compromised (not eligible)", compromised, now.Add(-30 * time.Second), "UNSATISFIED"},
		{"OAS-FACT-003", "approved 301s ago", clean, now.Add(-301 * time.Second), "UNSATISFIED"},
	} {
		probe := buildReport(f, c.spec, req, now, c.issuedAt, false)
		report := buildReport(f, c.spec, req, now, c.issuedAt, eligible(f, c.spec, probe))
		got := "not-evaluated"
		if report.Satisfaction != nil {
			got = string(report.Satisfaction.Satisfaction().Verdict)
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-32s want=%s got=%s\n", status, c.caseID, c.name, c.want, got)
	}
	fmt.Println()

	fmt.Println("4. Members with no CLC axis (residual, carrier or enforcement point)")
	for _, r := range f.Residuals {
		fmt.Println("   - " + r)
	}
	fmt.Println()
	fmt.Println("Reading: the same expectation inventory, closed outcomes and Fact lineage")
	fmt.Println("serve OASNT without a carrier-specific branch.  adg is not a CLC ActionId;")
	fmt.Println("the observation records both and the pinned mapping profile relates them.")
}
