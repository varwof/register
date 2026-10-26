// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command izmaylov-projection-probe projects the signature stage of an
// Izmaylov permission/receipt/log evidence set onto the CLC evidence report.
//
// Source: draft-izmaylov-agent-permission-receipts-00 §4 (signatures), §5
// (permission), §6 (action receipts), §9 (logs and tree heads), §10 (the three
// verification answers).
//
// The probe does not implement WebAuthn, Ed25519 or ML-DSA.  The fixture is
// synthetic evidence: each native check outcome is what a native verifier
// reported after running the real check.  What the probe tests is the
// projection: four-outcome results, expectation inventory, completeness, the
// three-answer summary, and the CLC verdict over the eligible receipt.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

// caseSpec is one fixture case: the modelled outcome per check, the native
// reasons, and the expected projection token.
type caseSpec struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Results map[string]string `json:"results"`
	Reasons map[string]string `json:"reasons"`
	Want    string            `json:"want"`
}

type checkSpec struct {
	CheckID        string            `json:"check_id"`
	ComponentType  string            `json:"component_type"`
	EvidenceDigest projection.Digest `json:"evidence_digest"`
	Note           string            `json:"note"`
}

type fixture struct {
	Version               string            `json:"@version"`
	Note                  string            `json:"note"`
	Now                   string            `json:"now"`
	Subject               string            `json:"subject"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	Permission            struct {
		ArtifactDigest projection.Digest `json:"artifact_digest"`
		ID             string            `json:"id"`
		Action         string            `json:"action"`
		Passes         int               `json:"passes"`
	} `json:"permission"`
	Receipt struct {
		ArtifactDigest projection.Digest `json:"artifact_digest"`
		ID             string            `json:"id"`
		Action         string            `json:"action"`
		Amount         string            `json:"amount"`
		Unit           string            `json:"unit"`
	} `json:"receipt"`
	Log struct {
		ArtifactDigest projection.Digest `json:"artifact_digest"`
		TreeSize       int               `json:"tree_size"`
		Root           projection.Digest `json:"root"`
	} `json:"log"`
	Checks    []checkSpec `json:"checks"`
	Residuals []string    `json:"residuals"`
	Cases     []caseSpec  `json:"cases"`
}

//go:embed testdata/izmaylov-signature-fixture-v1.json
var fixtureJSON []byte

//go:embed testdata/izmaylov-containment-fixture-v1.json
var containmentJSON []byte

//go:embed testdata/izmaylov-conditions-fixture-v1.json
var conditionsJSON []byte

//go:embed testdata/izmaylov-log-inclusion-fixture-v1.json
var logInclusionJSON []byte

//go:embed testdata/izmaylov-log-consistency-fixture-v1.json
var logConsistencyJSON []byte

type receiptEntry struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Amount *int   `json:"amount"`
	Unit   string `json:"unit"`
	When   string `json:"when"`
	With   string `json:"with"`
}

type limit struct {
	Action string `json:"action"`
	Max    *int   `json:"max"`
	Each   *int   `json:"each"`
	Count  *int   `json:"count"`
	Per    int    `json:"per"`
	Unit   string `json:"unit"`
}

type containmentCase struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Receipt   receiptEntry   `json:"receipt"`
	Log       []receiptEntry `json:"log"`
	Truncated bool           `json:"log_truncated"`
	Want      string         `json:"want"`
}

type containmentFixture struct {
	Version               string            `json:"@version"`
	Note                  string            `json:"note"`
	Now                   string            `json:"now"`
	Subject               string            `json:"subject"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	ReceiptDigest         projection.Digest `json:"receipt_digest"`
	Permission            struct {
		ID             string            `json:"id"`
		ArtifactDigest projection.Digest `json:"artifact_digest"`
		Actions        []string          `json:"actions"`
		Never          []string          `json:"never"`
		With           []string          `json:"with"`
		ValidFrom      string            `json:"valid_from"`
		ValidUntil     string            `json:"valid_until"`
		Limits         []limit           `json:"limits"`
	} `json:"permission"`
	Log       []receiptEntry    `json:"log"`
	Residuals []string          `json:"residuals"`
	Cases     []containmentCase `json:"cases"`
}

func loadContainment() containmentFixture {
	var f containmentFixture
	if err := json.Unmarshal(containmentJSON, &f); err != nil {
		panic(err)
	}
	return f
}

type condition struct {
	Need   string `json:"need"`
	Action string `json:"action"`
	Above  *int   `json:"above"`
	Unit   string `json:"unit"`
}

type service struct {
	ID      string `json:"id"`
	HasKeys bool   `json:"has_keys"`
}

type countersignature struct {
	Stub  projection.Digest `json:"stub"`
	Valid bool              `json:"valid"`
	When  string            `json:"when"`
}

type documentRef struct {
	Name   string            `json:"name"`
	SHA256 projection.Digest `json:"sha256"`
}

type approvalRecord struct {
	ID      string            `json:"id"`
	Slip    projection.Digest `json:"slip"`
	Action  string            `json:"action"`
	Amount  *int              `json:"amount"`
	Unit    string            `json:"unit"`
	With    string            `json:"with"`
	When    string            `json:"when"`
	Details []documentRef     `json:"details"`
	Valid   any               `json:"valid"`
}

type conditionReceipt struct {
	ID               string            `json:"id"`
	Action           string            `json:"action"`
	Amount           *int              `json:"amount"`
	Unit             string            `json:"unit"`
	When             string            `json:"when"`
	With             string            `json:"with"`
	Details          []documentRef     `json:"details"`
	Countersignature *countersignature `json:"countersignature"`
	Approval         *approvalRecord   `json:"approval"`
}

type cancellationRecord struct {
	ID    string `json:"id"`
	When  string `json:"when"`
	Sound bool   `json:"sound"`
}

type conditionCase struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	PermissionWith   []service           `json:"permission_with"`
	PriorApprovalIDs []string            `json:"prior_approval_ids"`
	Cancellation     *cancellationRecord `json:"cancellation"`
	Receipt          conditionReceipt    `json:"receipt"`
	Want             string              `json:"want"`
}

type conditionsFixture struct {
	Version               string            `json:"@version"`
	Now                   string            `json:"now"`
	Subject               string            `json:"subject"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	ReceiptDigest         projection.Digest `json:"receipt_digest"`
	Permission            struct {
		ID             string            `json:"id"`
		ArtifactDigest projection.Digest `json:"artifact_digest"`
		Action         string            `json:"action"`
		With           []service         `json:"with"`
		Requires       []condition       `json:"requires"`
	} `json:"permission"`
	Receipt   conditionReceipt `json:"receipt"`
	Residuals []string         `json:"residuals"`
	Cases     []conditionCase  `json:"cases"`
}

func loadConditions() conditionsFixture {
	var f conditionsFixture
	if err := json.Unmarshal(conditionsJSON, &f); err != nil {
		panic(err)
	}
	return f
}

type proofStep struct {
	Side string            `json:"side"`
	Hash projection.Digest `json:"hash"`
}

type logInclusionCase struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Leaf         projection.Digest `json:"leaf"`
	TreeHeadRoot projection.Digest `json:"tree_head_root"`
	Proof        *[]proofStep      `json:"proof"`
	Want         string            `json:"want"`
}

type logInclusionFixture struct {
	Version               string            `json:"@version"`
	Now                   string            `json:"now"`
	Subject               string            `json:"subject"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	TreeHead              struct {
		Root     projection.Digest `json:"root"`
		TreeSize int               `json:"tree_size"`
	} `json:"tree_head"`
	Leaf      projection.Digest  `json:"leaf"`
	Proof     []proofStep        `json:"proof"`
	Residuals []string           `json:"residuals"`
	Cases     []logInclusionCase `json:"cases"`
}

func loadLogInclusion() logInclusionFixture {
	var f logInclusionFixture
	if err := json.Unmarshal(logInclusionJSON, &f); err != nil {
		panic(err)
	}
	return f
}

// digestBytes decodes a canonical digest's hex payload.
func digestBytes(d projection.Digest) ([]byte, error) {
	raw := string(d)
	if len(raw) != len("sha-256:")+64 || raw[:len("sha-256:")] != "sha-256:" {
		return nil, fmt.Errorf("digest %q is not canonical", raw)
	}
	return hex.DecodeString(raw[len("sha-256:"):])
}

// verifyInclusion recomputes the Merkle root from the leaf and the supplied
// path, then compares it with the signed tree-head root.
func verifyInclusion(leaf projection.Digest, proof []proofStep, root projection.Digest) (bool, error) {
	node, err := digestBytes(leaf)
	if err != nil {
		return false, err
	}
	for _, step := range proof {
		sibling, err := digestBytes(step.Hash)
		if err != nil {
			return false, err
		}
		switch step.Side {
		case "left":
			sum := sha256.Sum256(append(append([]byte{}, sibling...), node...))
			node = sum[:]
		case "right":
			sum := sha256.Sum256(append(append([]byte{}, node...), sibling...))
			node = sum[:]
		default:
			return false, fmt.Errorf("proof side %q is not left|right", step.Side)
		}
	}
	return projection.DigestFromBytes(node) == root, nil
}

type logConsistencyCase struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Leaves        *[]projection.Digest `json:"leaves"`
	LeavesOmitted bool                 `json:"leaves_omitted"`
	OldRoot       projection.Digest    `json:"old_root"`
	NewSize       *int                 `json:"new_size"`
	Want          string               `json:"want"`
}

type logConsistencyFixture struct {
	Version               string            `json:"@version"`
	Now                   string            `json:"now"`
	Subject               string            `json:"subject"`
	Verifier              string            `json:"verifier"`
	VerifierProfileDigest projection.Digest `json:"verifier_profile_digest"`
	TrustSnapshotDigest   projection.Digest `json:"trust_snapshot_digest"`
	StatusSnapshotDigest  projection.Digest `json:"status_snapshot_digest"`
	ProfileDigest         projection.Digest `json:"profile_digest"`
	Old                   struct {
		Root projection.Digest `json:"root"`
		Size int               `json:"size"`
	} `json:"old"`
	New struct {
		Root projection.Digest `json:"root"`
		Size int               `json:"size"`
	} `json:"new"`
	Leaves    []projection.Digest  `json:"leaves"`
	Residuals []string             `json:"residuals"`
	Cases     []logConsistencyCase `json:"cases"`
}

func loadLogConsistency() logConsistencyFixture {
	var f logConsistencyFixture
	if err := json.Unmarshal(logConsistencyJSON, &f); err != nil {
		panic(err)
	}
	return f
}

// merkleRoot recomputes the tree root from the leaf set, promoting an unpaired
// last node at each level.
func merkleRoot(leaves []projection.Digest) (projection.Digest, error) {
	level := make([][]byte, 0, len(leaves))
	for _, leaf := range leaves {
		raw, err := digestBytes(leaf)
		if err != nil {
			return "", err
		}
		level = append(level, raw)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			sum := sha256.Sum256(append(append([]byte{}, level[i]...), level[i+1]...))
			next = append(next, sum[:])
		}
		level = next
	}
	if len(level) == 0 {
		return "", fmt.Errorf("empty leaf set")
	}
	return projection.DigestFromBytes(level[0]), nil
}

const checkLogAppendOnly = "izmaylov:log-append-only"

const checkLogInclusion = "izmaylov:log-inclusion"

const (
	checkCountersignature = "izmaylov:countersignature"
	checkApproval         = "izmaylov:approval"
	checkCancellation     = "izmaylov:cancellation"
)

var conditionFindingOrder = []string{
	"countersignature-missing",
	"countersignature-not-possible",
	"countersignature-wrong-stub",
	"countersignature-invalid",
	"approval-missing",
	"approval-mismatch",
	"approval-reused",
	"approval-invalid",
	"approval-dated-after-stub",
	"approval-unavailable",
	"after-cancellation",
}

const (
	checkAction   = "izmaylov:action-allowed"
	checkParty    = "izmaylov:party-allowed"
	checkValidity = "izmaylov:validity-window"
	checkLimits   = "izmaylov:limits"
)

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
  "requirement_id": "izmaylov-receipt@1",
  "expression": "izmaylov-receipt",
  "constraints": [
    {"role": "izmaylov-receipt", "constraint": "varwof/evidence-v1:freshness:sec:300"}
  ]
}`

func parseRequirement() semantics.Requirement {
	req, err := semantics.ParseRequirement([]byte(requirementDoc))
	if err != nil {
		panic(err)
	}
	return req
}

// checkFor returns the check spec for a check id.
func (f fixture) checkFor(id string) checkSpec {
	for _, check := range f.Checks {
		if check.CheckID == id {
			return check
		}
	}
	panic("unknown check " + id)
}

func buildResults(f fixture, c caseSpec, now time.Time) []projection.NativeCheckResult {
	results := make([]projection.NativeCheckResult, 0, len(f.Checks))
	for _, check := range f.Checks {
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
		}
		if outcome == string(projection.NativeCheckSuccess) || outcome == string(projection.NativeCheckFailed) {
			result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessFresh}
			// The log tree head is the status snapshot for this stage; a
			// deployer can pin its generation to reject rollback.
			result.StatusSnapshotSource = "izmaylov-log"
			result.StatusSnapshotGeneration = int64(f.Log.TreeSize)
		}
		results = append(results, result)
	}
	return results
}

// allSuccess reports whether every declared check has a success result and the
// inventory is complete.
func allSuccess(f fixture, results []projection.NativeCheckResult, assessment *projection.NativeCheckAssessment) bool {
	if assessment == nil || !assessment.Complete {
		return false
	}
	for _, check := range f.Checks {
		found := false
		for _, result := range results {
			if result.CheckID == check.CheckID &&
				result.EvidenceDigest == check.EvidenceDigest &&
				result.Outcome == projection.NativeCheckSuccess {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func gating(results []projection.NativeCheckResult, checkID string, digest projection.Digest) []string {
	for _, result := range results {
		if result.CheckID == checkID && result.EvidenceDigest == digest {
			return []string{checkID}
		}
	}
	return nil
}

func parseInstant(raw string) time.Time {
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		panic(err)
	}
	return value
}

func containsString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

// prohibitedAction applies the probe's simplified never rule: an exact name, or
// a "prefix.*" entry.  Appendix B's shared-action catalogue is out of scope.
func prohibitedAction(never []string, action string) bool {
	for _, entry := range never {
		if entry == action {
			return true
		}
		if strings.HasSuffix(entry, ".*") &&
			strings.HasPrefix(action, strings.TrimSuffix(entry, "*")) {
			return true
		}
	}
	return false
}

func outsideWindow(when, from, until string) bool {
	t := parseInstant(when)
	return t.Before(parseInstant(from)) || !t.Before(parseInstant(until))
}

// inPeriod reports whether event i falls in the period ending at t, per §10.2:
// later than t-P, and not later than t.
func inPeriod(events []receiptEntry, i int, t time.Time, per int) bool {
	if per <= 0 {
		return true
	}
	when := parseInstant(events[i].When)
	return when.After(t.Add(-time.Duration(per)*time.Second)) && !when.After(t)
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// evaluateLimits applies §5.1/§10.2 arithmetic to the ordered log.  Only the
// current receipt is checked for amount-missing; prior entries are assumed to
// have been verified already.
func evaluateLimits(f containmentFixture, c containmentCase) []string {
	prior := c.Log
	if len(prior) == 0 {
		prior = f.Log
	}
	events := append(append([]receiptEntry{}, prior...), c.Receipt)
	t := parseInstant(c.Receipt.When)
	var found []string
	for _, lim := range f.Permission.Limits {
		if lim.Action != c.Receipt.Action {
			continue
		}
		switch {
		case lim.Max != nil:
			if c.Receipt.Amount == nil || c.Receipt.Unit != lim.Unit {
				found = append(found, "amount-missing")
				continue
			}
			total := 0
			for i, e := range events {
				if e.Action != lim.Action || e.Amount == nil || e.Unit != lim.Unit {
					continue
				}
				if !inPeriod(events, i, t, lim.Per) {
					continue
				}
				total += *e.Amount
			}
			if total > *lim.Max {
				if lim.Per > 0 {
					found = append(found, "over-period-limit")
				} else {
					found = append(found, "over-limit")
				}
			}
		case lim.Each != nil:
			if c.Receipt.Amount == nil || c.Receipt.Unit != lim.Unit {
				found = append(found, "amount-missing")
				continue
			}
			if *c.Receipt.Amount > *lim.Each {
				found = append(found, "over-each-limit")
			}
		case lim.Count != nil:
			count := 0
			for i, e := range events {
				if e.Action != lim.Action {
					continue
				}
				if !inPeriod(events, i, t, lim.Per) {
					continue
				}
				count++
			}
			if count > *lim.Count {
				found = append(found, "over-count-limit")
			}
		}
	}
	return dedupe(found)
}

// findingOrder is the stable order findings are reported in.
var findingOrder = []string{
	"action-not-allowed",
	"prohibited",
	"party-not-allowed",
	"outside-valid-time",
	"amount-missing",
	"over-limit",
	"over-each-limit",
	"over-count-limit",
	"over-period-limit",
	"limits-unavailable",
}

// assessContainment computes the containment checks and the §10.2 findings for
// one case.  It returns the outcome per check, the native reason per check, and
// the findings in stable order.
func assessContainment(f containmentFixture, c containmentCase) (map[string]string, map[string]string, []string) {
	outcomes := map[string]string{
		checkAction:   string(projection.NativeCheckSuccess),
		checkParty:    string(projection.NativeCheckSuccess),
		checkValidity: string(projection.NativeCheckSuccess),
		checkLimits:   string(projection.NativeCheckSuccess),
	}
	reasons := map[string]string{}
	findings := make(map[string]bool)

	actionAllowed := containsString(f.Permission.Actions, c.Receipt.Action)
	if !actionAllowed {
		findings["action-not-allowed"] = true
		outcomes[checkAction] = string(projection.NativeCheckFailed)
	}
	if prohibitedAction(f.Permission.Never, c.Receipt.Action) {
		findings["prohibited"] = true
		outcomes[checkAction] = string(projection.NativeCheckFailed)
	}
	if !containsString(f.Permission.With, c.Receipt.With) {
		findings["party-not-allowed"] = true
		outcomes[checkParty] = string(projection.NativeCheckFailed)
	}
	if outsideWindow(c.Receipt.When, f.Permission.ValidFrom, f.Permission.ValidUntil) {
		findings["outside-valid-time"] = true
		outcomes[checkValidity] = string(projection.NativeCheckFailed)
	}

	switch {
	case !actionAllowed:
		// Limits name actions, so an action outside the permission has no
		// limit to evaluate.  This is not a failed check.
		outcomes[checkLimits] = string(projection.NativeCheckNotApplicable)
	case c.Truncated:
		findings["limits-unavailable"] = true
		outcomes[checkLimits] = string(projection.NativeCheckUnavailable)
	default:
		for _, finding := range evaluateLimits(f, c) {
			findings[finding] = true
			outcomes[checkLimits] = string(projection.NativeCheckFailed)
		}
	}

	for _, check := range []string{checkAction, checkParty, checkValidity, checkLimits} {
		switch outcomes[check] {
		case string(projection.NativeCheckNotApplicable):
			reasons[check] = "izmaylov:action-not-allowed"
		case string(projection.NativeCheckUnavailable):
			reasons[check] = "izmaylov:log-truncated"
		}
	}
	for finding := range findings {
		if finding == "limits-unavailable" {
			continue
		}
		check := checkAction
		switch finding {
		case "party-not-allowed":
			check = checkParty
		case "outside-valid-time":
			check = checkValidity
		case "amount-missing", "over-limit", "over-each-limit", "over-count-limit", "over-period-limit":
			check = checkLimits
		}
		if reasons[check] == "" {
			reasons[check] = "izmaylov:" + finding
		}
	}

	ordered := make([]string, 0, len(findings))
	for _, finding := range findingOrder {
		if findings[finding] {
			ordered = append(ordered, finding)
		}
	}
	return outcomes, reasons, ordered
}

func (c conditionCase) mergedReceipt(f conditionsFixture) conditionReceipt {
	receipt := c.Receipt
	base := f.Receipt
	if receipt.ID == "" {
		receipt.ID = base.ID
	}
	if receipt.Action == "" {
		receipt.Action = base.Action
	}
	if receipt.Unit == "" {
		receipt.Unit = base.Unit
	}
	if receipt.When == "" {
		receipt.When = base.When
	}
	if receipt.With == "" {
		receipt.With = base.With
	}
	if receipt.Amount == nil {
		receipt.Amount = base.Amount
	}
	if len(receipt.Details) == 0 {
		receipt.Details = base.Details
	}
	return receipt
}

// conditionApplies implements §5.1: a condition with "above" applies only when
// the receipt has an amount in the condition's unit and above the threshold.
func conditionApplies(cond condition, r conditionReceipt) bool {
	if cond.Action != "" && cond.Action != r.Action {
		return false
	}
	if cond.Above != nil {
		if r.Amount == nil || r.Unit != cond.Unit {
			return false
		}
		if *r.Amount <= *cond.Above {
			return false
		}
	}
	return true
}

func serviceHasKeys(services []service, id string) bool {
	for _, svc := range services {
		if svc.ID == id {
			return svc.HasKeys
		}
	}
	return false
}

func detailsEqual(a, b []documentRef) bool {
	if len(a) != len(b) {
		return false
	}
	index := make(map[string]projection.Digest, len(a))
	for _, doc := range a {
		index[doc.Name] = doc.SHA256
	}
	for _, doc := range b {
		value, ok := index[doc.Name]
		if !ok || value != doc.SHA256 {
			return false
		}
	}
	return true
}

func approvalMatches(ap *approvalRecord, r conditionReceipt, permissionDigest projection.Digest) bool {
	if ap.Slip != permissionDigest {
		return false
	}
	if ap.Action != r.Action || ap.Unit != r.Unit || ap.With != r.With {
		return false
	}
	if !detailsEqual(ap.Details, r.Details) {
		return false
	}
	if (ap.Amount == nil) != (r.Amount == nil) {
		return false
	}
	if ap.Amount != nil && *ap.Amount != *r.Amount {
		return false
	}
	return true
}

func approvalState(ap *approvalRecord) (valid, unsupported bool) {
	switch value := ap.Valid.(type) {
	case bool:
		return value, false
	case string:
		return false, value == "unsupported"
	default:
		return false, false
	}
}

func assessConditions(f conditionsFixture, c conditionCase) (map[string]string, map[string]string, []string) {
	r := c.mergedReceipt(f)
	services := f.Permission.With
	if len(c.PermissionWith) > 0 {
		services = c.PermissionWith
	}
	outcomes := map[string]string{
		checkCountersignature: string(projection.NativeCheckSuccess),
		checkApproval:         string(projection.NativeCheckSuccess),
		checkCancellation:     string(projection.NativeCheckSuccess),
	}
	reasons := map[string]string{}
	findings := make(map[string]bool)

	countersignatureRequired := false
	approvalRequired := false
	for _, cond := range f.Permission.Requires {
		if !conditionApplies(cond, r) {
			continue
		}
		switch cond.Need {
		case "countersignature":
			countersignatureRequired = true
		case "approval":
			approvalRequired = true
		}
	}

	if countersignatureRequired {
		switch {
		case r.Countersignature == nil:
			findings["countersignature-missing"] = true
		case !serviceHasKeys(services, r.With):
			findings["countersignature-not-possible"] = true
		case r.Countersignature.Stub != f.ReceiptDigest:
			findings["countersignature-wrong-stub"] = true
		case !r.Countersignature.Valid:
			findings["countersignature-invalid"] = true
		}
		for _, finding := range conditionFindingOrder {
			if strings.HasPrefix(finding, "countersignature-") && findings[finding] {
				outcomes[checkCountersignature] = string(projection.NativeCheckFailed)
				break
			}
		}
	}

	if approvalRequired {
		switch {
		case r.Approval == nil:
			findings["approval-missing"] = true
		case !approvalMatches(r.Approval, r, f.Permission.ArtifactDigest):
			findings["approval-mismatch"] = true
		case containsString(c.PriorApprovalIDs, r.Approval.ID):
			findings["approval-reused"] = true
		default:
			valid, unsupported := approvalState(r.Approval)
			switch {
			case unsupported:
				findings["approval-unavailable"] = true
				outcomes[checkApproval] = string(projection.NativeCheckUnavailable)
			case !valid:
				findings["approval-invalid"] = true
			case parseInstant(r.Approval.When).After(parseInstant(r.When).Add(300 * time.Second)):
				findings["approval-dated-after-stub"] = true
			}
		}
		if outcomes[checkApproval] == string(projection.NativeCheckSuccess) {
			for _, finding := range conditionFindingOrder {
				if strings.HasPrefix(finding, "approval-") && finding != "approval-unavailable" && findings[finding] {
					outcomes[checkApproval] = string(projection.NativeCheckFailed)
					break
				}
			}
		}
	}

	if c.Cancellation != nil && c.Cancellation.Sound &&
		!parseInstant(c.Cancellation.When).After(parseInstant(r.When)) {
		findings["after-cancellation"] = true
		outcomes[checkCancellation] = string(projection.NativeCheckFailed)
	}

	for _, finding := range conditionFindingOrder {
		if !findings[finding] {
			continue
		}
		check := checkApproval
		switch {
		case strings.HasPrefix(finding, "countersignature-"):
			check = checkCountersignature
		case finding == "after-cancellation":
			check = checkCancellation
		}
		if reasons[check] == "" {
			reasons[check] = "izmaylov:" + finding
		}
	}
	ordered := make([]string, 0, len(findings))
	for _, finding := range conditionFindingOrder {
		if findings[finding] {
			ordered = append(ordered, finding)
		}
	}
	return outcomes, reasons, ordered
}

func main() {
	f := loadFixture()
	now := f.now()
	req := parseRequirement()

	fmt.Println("Izmaylov permission/receipt/log → CLC evidence projection (signature stage)")
	fmt.Println("Source: draft-izmaylov-agent-permission-receipts-00 §4/§5/§6/§9/§10 (checked 2026-10-25)")
	fmt.Println("Fixture: synthetic evidence; WebAuthn, Ed25519 and ML-DSA are modelled, not executed")
	fmt.Printf("subject: %s\n", f.Subject)
	fmt.Printf("permission %s → action %s (passes=%d)\n", f.Permission.ID, f.Permission.Action, f.Permission.Passes)
	fmt.Printf("receipt %s → action %s amount %s %s\n", f.Receipt.ID, f.Receipt.Action, f.Receipt.Amount, f.Receipt.Unit)
	fmt.Printf("log tree_size=%d root=%s\n", f.Log.TreeSize, f.Log.Root)
	fmt.Println()

	expectations := make([]projection.NativeCheckExpectation, 0, len(f.Checks))
	required := make([]string, 0, len(f.Checks))
	for _, check := range f.Checks {
		expectations = append(expectations, projection.NativeCheckExpectation{
			CheckID:        check.CheckID,
			ComponentType:  check.ComponentType,
			EvidenceDigest: check.EvidenceDigest,
		})
		required = append(required, check.CheckID)
	}
	profile := &projection.Profile{
		ID:              "izmaylov/signature-stage-v1",
		StatusModel:     projection.StatusRequired,
		ReasonNamespace: "izmaylov",
		RequiredChecks:  required,
		Expectations:    expectations,
		ProfileDigest:   f.ProfileDigest,
	}
	if err := profile.Seal(); err != nil {
		panic(err)
	}

	fmt.Println("1. Signature-stage checks and the three verification answers")
	for _, c := range f.Cases {
		results := buildResults(f, c, now)
		assessment := projection.AssessNativeChecks(expectations, results)
		eligible := allSuccess(f, results, &assessment)

		records := make([]projection.ProjectedEvidenceRecord, 0, len(f.Checks))
		var fact *semantics.EvidenceFact
		if eligible {
			value := semantics.EvidenceFact{
				Type: "izmaylov-receipt", Subject: f.Receipt.ID, Verified: true,
				IssuedAt: now.Add(-30 * time.Second),
			}
			fact = &value
		}
		for _, check := range f.Checks {
			record := projection.ProjectedEvidenceRecord{
				ArtifactDigest: check.EvidenceDigest,
				NativeCheckIDs: gating(results, check.CheckID, check.EvidenceDigest),
			}
			if check.CheckID == "izmaylov:receipt-signature" {
				record.Fact = fact
			}
			records = append(records, record)
		}

		facts := []semantics.EvidenceFact{}
		if fact != nil {
			facts = append(facts, *fact)
		}

		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:             "izmaylov/permission-receipt-log-v1",
			SourceFormat:            "IZMAYLOV-PROVARED-v0/signature-stage",
			Meta:                    map[string]string{"mapped_at_utc": now.UTC().Format(time.RFC3339)},
			Requirement:             &req,
			RequiredNativeChecks:    required,
			NativeCheckExpectations: expectations,
			NativeCheckResults:      results,
			Facts:                   facts,
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

		problem := "none"
		for _, result := range results {
			if result.Outcome == projection.NativeCheckFailed {
				problem = "found"
				break
			}
		}
		verified := "partial"
		if report.NativeChecksComplete {
			verified = "all"
			for _, result := range results {
				if result.Outcome == projection.NativeCheckUnavailable {
					verified = "partial"
					break
				}
			}
		}
		satisfaction := "not-evaluated"
		if report.Satisfaction != nil {
			satisfaction = string(report.Satisfaction.Satisfaction().Verdict)
		}
		got := fmt.Sprintf("problem=%s,verified=%s,eligible=%t,satisfaction=%s",
			problem, verified, eligible, satisfaction)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		detail := "permission=not-evaluated"
		if missing := len(assessment.MissingExpectations); missing > 0 {
			detail += fmt.Sprintf(" missing=%d", missing)
		}
		fmt.Printf("%s %s %-56s %s want=%s got=%s\n", status, c.ID, c.Name, detail, c.Want, got)
	}
	fmt.Println()

	fmt.Println("2. Permission containment (actions / never / with / validity / limits)")
	cf := loadContainment()
	cNow := parseInstant(cf.Now)
	cReq := parseRequirement()
	containmentChecks := []string{checkAction, checkParty, checkValidity, checkLimits}
	containmentExpectations := make([]projection.NativeCheckExpectation, 0, len(containmentChecks))
	for _, check := range containmentChecks {
		containmentExpectations = append(containmentExpectations, projection.NativeCheckExpectation{
			CheckID:        check,
			ComponentType:  "izmaylov:action-receipt",
			EvidenceDigest: cf.ReceiptDigest,
		})
	}
	containmentProfile := &projection.Profile{
		ID:                     "izmaylov/containment-v1",
		StatusModel:            projection.StatusRequired,
		ReasonNamespace:        "izmaylov",
		RequiredChecks:         containmentChecks,
		Expectations:           containmentExpectations,
		NotApplicableAuthority: cf.VerifierProfileDigest,
		ProfileDigest:          cf.ProfileDigest,
	}
	if err := containmentProfile.Seal(); err != nil {
		panic(err)
	}
	for _, c := range cf.Cases {
		outcomes, reasons, findings := assessContainment(cf, c)
		results := make([]projection.NativeCheckResult, 0, len(containmentChecks))
		for _, check := range containmentChecks {
			result := projection.NativeCheckResult{
				CheckID:               check,
				ComponentType:         "izmaylov:action-receipt",
				EvidenceDigest:        cf.ReceiptDigest,
				Outcome:               projection.NativeCheckOutcome(outcomes[check]),
				Reason:                reasons[check],
				Verifier:              cf.Verifier,
				VerifierProfileDigest: cf.VerifierProfileDigest,
				TrustSnapshotDigest:   cf.TrustSnapshotDigest,
				StatusSnapshotDigest:  cf.StatusSnapshotDigest,
				VerificationTime:      cNow,
			}
			if result.Outcome == projection.NativeCheckSuccess ||
				result.Outcome == projection.NativeCheckFailed {
				result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessFresh}
			}
			results = append(results, result)
		}
		assessment := projection.AssessNativeChecks(containmentExpectations, results)
		eligible := assessment.Complete
		for _, result := range results {
			if result.Outcome != projection.NativeCheckSuccess {
				eligible = false
			}
		}

		var fact *semantics.EvidenceFact
		if eligible {
			value := semantics.EvidenceFact{
				Type:     "izmaylov-receipt",
				Subject:  c.Receipt.ID,
				Verified: true,
				IssuedAt: parseInstant(c.Receipt.When),
			}
			fact = &value
		}
		gating := make([]string, 0, len(results))
		for _, result := range results {
			gating = append(gating, result.CheckID)
		}
		records := []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: cf.ReceiptDigest,
			Fact:           fact,
			NativeCheckIDs: gating,
		}}
		facts := []semantics.EvidenceFact{}
		if fact != nil {
			facts = append(facts, *fact)
		}

		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:             "izmaylov/permission-receipt-log-v1",
			SourceFormat:            "IZMAYLOV-PROVARED-v0/containment-stage",
			Meta:                    map[string]string{"mapped_at_utc": cNow.UTC().Format(time.RFC3339)},
			Requirement:             &cReq,
			RequiredNativeChecks:    containmentChecks,
			NativeCheckExpectations: containmentExpectations,
			NativeCheckResults:      results,
			Facts:                   facts,
			EvidenceRecords:         records,
			Profile:                 containmentProfile,
			Verifier: &projection.VerifierIdentity{
				Principal:             cf.Verifier,
				VerifierProfileDigest: cf.VerifierProfileDigest,
			},
			Residuals: cf.Residuals,
			Now:       cNow,
		})
		if err != nil {
			panic(err)
		}
		satisfaction := "not-evaluated"
		if report.Satisfaction != nil {
			satisfaction = string(report.Satisfaction.Satisfaction().Verdict)
		}
		findingsToken := "none"
		if len(findings) > 0 {
			findingsToken = strings.Join(findings, "+")
		}
		got := fmt.Sprintf("findings=%s,eligible=%t,satisfaction=%s",
			findingsToken, eligible, satisfaction)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-56s want=%s got=%s\n", status, c.ID, c.Name, c.Want, got)
	}
	fmt.Println()

	fmt.Println("3. Conditions: countersignature, approval and cancellation")
	cf2 := loadConditions()
	condNow := parseInstant(cf2.Now)
	conditionChecks := []string{checkCountersignature, checkApproval, checkCancellation}
	conditionExpectations := make([]projection.NativeCheckExpectation, 0, len(conditionChecks))
	for _, check := range conditionChecks {
		conditionExpectations = append(conditionExpectations, projection.NativeCheckExpectation{
			CheckID:        check,
			ComponentType:  "izmaylov:action-receipt",
			EvidenceDigest: cf2.ReceiptDigest,
		})
	}
	conditionProfile := &projection.Profile{
		ID:              "izmaylov/conditions-v1",
		StatusModel:     projection.StatusRequired,
		ReasonNamespace: "izmaylov",
		RequiredChecks:  conditionChecks,
		Expectations:    conditionExpectations,
		ProfileDigest:   cf2.ProfileDigest,
	}
	if err := conditionProfile.Seal(); err != nil {
		panic(err)
	}
	for _, c := range cf2.Cases {
		outcomes, reasons, findings := assessConditions(cf2, c)
		receipt := c.mergedReceipt(cf2)
		results := make([]projection.NativeCheckResult, 0, len(conditionChecks))
		for _, check := range conditionChecks {
			result := projection.NativeCheckResult{
				CheckID:               check,
				ComponentType:         "izmaylov:action-receipt",
				EvidenceDigest:        cf2.ReceiptDigest,
				Outcome:               projection.NativeCheckOutcome(outcomes[check]),
				Reason:                reasons[check],
				Verifier:              cf2.Verifier,
				VerifierProfileDigest: cf2.VerifierProfileDigest,
				TrustSnapshotDigest:   cf2.TrustSnapshotDigest,
				StatusSnapshotDigest:  cf2.StatusSnapshotDigest,
				VerificationTime:      condNow,
			}
			if result.Outcome == projection.NativeCheckSuccess ||
				result.Outcome == projection.NativeCheckFailed {
				result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessFresh}
			}
			results = append(results, result)
		}
		assessment := projection.AssessNativeChecks(conditionExpectations, results)
		eligible := assessment.Complete
		for _, result := range results {
			if result.Outcome != projection.NativeCheckSuccess {
				eligible = false
			}
		}
		var fact *semantics.EvidenceFact
		if eligible {
			value := semantics.EvidenceFact{
				Type:     "izmaylov-receipt",
				Subject:  receipt.ID,
				Verified: true,
				IssuedAt: parseInstant(receipt.When),
			}
			fact = &value
		}
		gating := make([]string, 0, len(results))
		for _, result := range results {
			gating = append(gating, result.CheckID)
		}
		records := []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: cf2.ReceiptDigest,
			Fact:           fact,
			NativeCheckIDs: gating,
		}}
		facts := []semantics.EvidenceFact{}
		if fact != nil {
			facts = append(facts, *fact)
		}
		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:             "izmaylov/permission-receipt-log-v1",
			SourceFormat:            "IZMAYLOV-PROVARED-v0/conditions-stage",
			Meta:                    map[string]string{"mapped_at_utc": condNow.UTC().Format(time.RFC3339)},
			Requirement:             &cReq,
			RequiredNativeChecks:    conditionChecks,
			NativeCheckExpectations: conditionExpectations,
			NativeCheckResults:      results,
			Facts:                   facts,
			EvidenceRecords:         records,
			Profile:                 conditionProfile,
			Verifier: &projection.VerifierIdentity{
				Principal:             cf2.Verifier,
				VerifierProfileDigest: cf2.VerifierProfileDigest,
			},
			Residuals: cf2.Residuals,
			Now:       condNow,
		})
		if err != nil {
			panic(err)
		}
		satisfaction := "not-evaluated"
		if report.Satisfaction != nil {
			satisfaction = string(report.Satisfaction.Satisfaction().Verdict)
		}
		findingsToken := "none"
		if len(findings) > 0 {
			findingsToken = strings.Join(findings, "+")
		}
		got := fmt.Sprintf("findings=%s,eligible=%t,satisfaction=%s",
			findingsToken, eligible, satisfaction)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-56s want=%s got=%s\n", status, c.ID, c.Name, c.Want, got)
	}
	fmt.Println()

	fmt.Println("4. Log inclusion (real SHA-256 Merkle proof verification)")
	lf := loadLogInclusion()
	logNow := parseInstant(lf.Now)
	inclusionChecks := []string{checkLogInclusion}
	for _, c := range lf.Cases {
		leaf := c.Leaf
		if leaf.Empty() {
			leaf = lf.Leaf
		}
		root := c.TreeHeadRoot
		if root.Empty() {
			root = lf.TreeHead.Root
		}
		proof := lf.Proof
		if c.Proof != nil {
			proof = *c.Proof
		}

		outcome := projection.NativeCheckSuccess
		reason := ""
		findings := "none"
		switch {
		case len(proof) == 0:
			outcome = projection.NativeCheckUnavailable
			reason = "izmaylov:inclusion-unavailable"
			findings = "inclusion-unavailable"
		default:
			ok, err := verifyInclusion(leaf, proof, root)
			switch {
			case err != nil:
				outcome = projection.NativeCheckFailed
				reason = "izmaylov:inclusion-invalid"
				findings = "inclusion-invalid"
			case !ok:
				outcome = projection.NativeCheckFailed
				reason = "izmaylov:inclusion-mismatch"
				findings = "inclusion-mismatch"
			}
		}

		result := projection.NativeCheckResult{
			CheckID:               checkLogInclusion,
			ComponentType:         "izmaylov:action-receipt",
			EvidenceDigest:        leaf,
			Outcome:               outcome,
			Reason:                reason,
			Verifier:              lf.Verifier,
			VerifierProfileDigest: lf.VerifierProfileDigest,
			TrustSnapshotDigest:   lf.TrustSnapshotDigest,
			StatusSnapshotDigest:  lf.StatusSnapshotDigest,
			VerificationTime:      logNow,
		}
		if outcome == projection.NativeCheckSuccess || outcome == projection.NativeCheckFailed {
			result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessFresh}
		}
		expectations := []projection.NativeCheckExpectation{{
			CheckID:        checkLogInclusion,
			ComponentType:  "izmaylov:action-receipt",
			EvidenceDigest: leaf,
		}}
		profile := &projection.Profile{
			ID:              "izmaylov/log-inclusion-v1",
			StatusModel:     projection.StatusRequired,
			ReasonNamespace: "izmaylov",
			RequiredChecks:  inclusionChecks,
			Expectations:    expectations,
			ProfileDigest:   lf.ProfileDigest,
		}
		if err := profile.Seal(); err != nil {
			panic(err)
		}
		eligible := outcome == projection.NativeCheckSuccess
		var fact *semantics.EvidenceFact
		if eligible {
			value := semantics.EvidenceFact{
				Type:     "izmaylov-receipt",
				Subject:  lf.Subject,
				Verified: true,
				IssuedAt: logNow.Add(-time.Minute),
			}
			fact = &value
		}
		records := []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: leaf,
			Fact:           fact,
			NativeCheckIDs: inclusionChecks,
		}}
		facts := []semantics.EvidenceFact{}
		if fact != nil {
			facts = append(facts, *fact)
		}
		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:             "izmaylov/permission-receipt-log-v1",
			SourceFormat:            "IZMAYLOV-PROVARED-v0/log-inclusion-stage",
			Meta:                    map[string]string{"mapped_at_utc": logNow.UTC().Format(time.RFC3339)},
			Requirement:             &cReq,
			RequiredNativeChecks:    inclusionChecks,
			NativeCheckExpectations: expectations,
			NativeCheckResults:      []projection.NativeCheckResult{result},
			Facts:                   facts,
			EvidenceRecords:         records,
			Profile:                 profile,
			Verifier: &projection.VerifierIdentity{
				Principal:             lf.Verifier,
				VerifierProfileDigest: lf.VerifierProfileDigest,
			},
			Residuals: lf.Residuals,
			Now:       logNow,
		})
		if err != nil {
			panic(err)
		}
		satisfaction := "not-evaluated"
		if report.Satisfaction != nil {
			satisfaction = string(report.Satisfaction.Satisfaction().Verdict)
		}
		got := fmt.Sprintf("findings=%s,eligible=%t,satisfaction=%s",
			findings, eligible, satisfaction)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-56s want=%s got=%s\n", status, c.ID, c.Name, c.Want, got)
	}
	fmt.Println()

	fmt.Println("5. Log append-only consistency (roots recomputed from the leaf set)")
	lc := loadLogConsistency()
	appendNow := parseInstant(lc.Now)
	for _, c := range lc.Cases {
		leaves := lc.Leaves
		if c.Leaves != nil {
			leaves = *c.Leaves
		}
		if c.LeavesOmitted {
			leaves = nil
		}
		oldRoot := lc.Old.Root
		if !c.OldRoot.Empty() {
			oldRoot = c.OldRoot
		}
		newSize := lc.New.Size
		if c.NewSize != nil {
			newSize = *c.NewSize
		}

		outcome := projection.NativeCheckSuccess
		reason := ""
		findings := "none"
		switch {
		case len(leaves) == 0 || lc.Old.Size > len(leaves) || newSize > len(leaves):
			outcome = projection.NativeCheckUnavailable
			reason = "izmaylov:consistency-unavailable"
			findings = "consistency-unavailable"
		case newSize < lc.Old.Size:
			outcome = projection.NativeCheckFailed
			reason = "izmaylov:consistency-truncated"
			findings = "consistency-truncated"
		default:
			recomputedOld, err := merkleRoot(leaves[:lc.Old.Size])
			if err != nil {
				panic(err)
			}
			recomputedNew, err := merkleRoot(leaves[:newSize])
			if err != nil {
				panic(err)
			}
			if recomputedOld != oldRoot || recomputedNew != lc.New.Root {
				outcome = projection.NativeCheckFailed
				reason = "izmaylov:consistency-mismatch"
				findings = "consistency-mismatch"
			}
		}

		result := projection.NativeCheckResult{
			CheckID:               checkLogAppendOnly,
			ComponentType:         "izmaylov:log",
			EvidenceDigest:        lc.New.Root,
			Outcome:               outcome,
			Reason:                reason,
			Verifier:              lc.Verifier,
			VerifierProfileDigest: lc.VerifierProfileDigest,
			TrustSnapshotDigest:   lc.TrustSnapshotDigest,
			StatusSnapshotDigest:  lc.StatusSnapshotDigest,
			VerificationTime:      appendNow,
		}
		if outcome == projection.NativeCheckSuccess || outcome == projection.NativeCheckFailed {
			result.FreshnessDecision = &projection.FreshnessDecision{Verdict: projection.FreshnessFresh}
		}
		expectations := []projection.NativeCheckExpectation{{
			CheckID:        checkLogAppendOnly,
			ComponentType:  "izmaylov:log",
			EvidenceDigest: lc.New.Root,
		}}
		profile := &projection.Profile{
			ID:              "izmaylov/log-append-only-v1",
			StatusModel:     projection.StatusRequired,
			ReasonNamespace: "izmaylov",
			RequiredChecks:  []string{checkLogAppendOnly},
			Expectations:    expectations,
			ProfileDigest:   lc.ProfileDigest,
		}
		if err := profile.Seal(); err != nil {
			panic(err)
		}
		eligible := outcome == projection.NativeCheckSuccess
		var fact *semantics.EvidenceFact
		if eligible {
			value := semantics.EvidenceFact{
				Type:     "izmaylov-receipt",
				Subject:  lc.Subject,
				Verified: true,
				IssuedAt: appendNow.Add(-time.Minute),
			}
			fact = &value
		}
		records := []projection.ProjectedEvidenceRecord{{
			ArtifactDigest: lc.New.Root,
			Fact:           fact,
			NativeCheckIDs: []string{checkLogAppendOnly},
		}}
		facts := []semantics.EvidenceFact{}
		if fact != nil {
			facts = append(facts, *fact)
		}
		report, err := projection.BuildEvidenceReport(projection.EvidenceInputs{
			ProjectorID:             "izmaylov/permission-receipt-log-v1",
			SourceFormat:            "IZMAYLOV-PROVARED-v0/log-append-only-stage",
			Meta:                    map[string]string{"mapped_at_utc": appendNow.UTC().Format(time.RFC3339)},
			Requirement:             &cReq,
			RequiredNativeChecks:    []string{checkLogAppendOnly},
			NativeCheckExpectations: expectations,
			NativeCheckResults:      []projection.NativeCheckResult{result},
			Facts:                   facts,
			EvidenceRecords:         records,
			Profile:                 profile,
			Verifier: &projection.VerifierIdentity{
				Principal:             lc.Verifier,
				VerifierProfileDigest: lc.VerifierProfileDigest,
			},
			Residuals: lc.Residuals,
			Now:       appendNow,
		})
		if err != nil {
			panic(err)
		}
		satisfaction := "not-evaluated"
		if report.Satisfaction != nil {
			satisfaction = string(report.Satisfaction.Satisfaction().Verdict)
		}
		got := fmt.Sprintf("findings=%s,eligible=%t,satisfaction=%s",
			findings, eligible, satisfaction)
		status := "PASS"
		if got != c.Want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-56s want=%s got=%s\n", status, c.ID, c.Name, c.Want, got)
	}
	fmt.Println()

	fmt.Println("6. Residuals (carrier, enforcement point or not yet projected)")
	for _, r := range f.Residuals {
		fmt.Println("   - " + r)
	}
	for _, r := range cf.Residuals {
		fmt.Println("   - " + r)
	}
	for _, r := range cf2.Residuals {
		fmt.Println("   - " + r)
	}
	for _, r := range lf.Residuals {
		fmt.Println("   - " + r)
	}
	for _, r := range lc.Residuals {
		fmt.Println("   - " + r)
	}
	fmt.Println()
	fmt.Println("Reading: `failed` is a check that ran and rejected; `unavailable` is a check")
	fmt.Println("that could not be run.  Izmaylov's answer 2 (\"was everything verified?\")")
	fmt.Println("is `verified=all|partial`, answer 1 is `problem=none|found`, and answer 3")
	fmt.Println("(within permission) is deliberately reported as not evaluated until the")
	fmt.Println("permission-containment stage lands.")
}
