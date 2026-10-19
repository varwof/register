// extension-parity-run emits the Go result for the shared three-language
// canonical parity fixture.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

type fixtureFact struct {
	Type     string `json:"type"`
	Subject  string `json:"subject"`
	IssuedAt string `json:"issued_at"`
	Verified bool   `json:"verified"`
}

type challengeFixture struct {
	ID             string         `json:"id"`
	Nonce          string         `json:"nonce"`
	Audience       string         `json:"audience"`
	ActionMaterial map[string]any `json:"action_material"`
	Now            string         `json:"now"`
	TTLSeconds     int64          `json:"ttl_sec"`
	RetryTiming    *struct {
		NotBefore string `json:"not_before"`
		JitterSec int    `json:"jitter_sec"`
	} `json:"retry_timing"`
}

type fixture struct {
	Version           string                         `json:"@version"`
	Grant             semantics.Grant                `json:"grant"`
	Operation         semantics.Operation            `json:"operation"`
	Context           semantics.DecisionContext      `json:"context"`
	ChallengeDecision semantics.Decision             `json:"challenge_decision"`
	ChallengeParams   challengeFixture               `json:"challenge_params"`
	ActionDefinition  semantics.ActionTypeDefinition `json:"action_definition"`
	Action            map[string]any                 `json:"action"`
	SourceChain       struct {
		AuthorityMaterial map[string]any `json:"authority_material"`
		ArtifactMaterial  map[string]any `json:"artifact_material"`
	} `json:"source_chain"`
	Requirement        semantics.Requirement `json:"requirement"`
	Facts              []fixtureFact         `json:"facts"`
	RequirementContext struct {
		Now       string `json:"now"`
		Initiator string `json:"initiator"`
		Executor  string `json:"executor"`
	} `json:"requirement_context"`
	Expect output `json:"expect"`
}

type output struct {
	RecordCanonicalSHA256 string            `json:"record_canonical_sha256"`
	ContextDigest         semantics.Digest  `json:"context_digest"`
	ChallengeDigest       semantics.Digest  `json:"challenge_digest"`
	ActionID              string            `json:"action_id"`
	EnvelopePayloadSHA256 string            `json:"envelope_payload_sha256"`
	SourceChainDigest     semantics.Digest  `json:"source_chain_digest"`
	StandingIDs           []string          `json:"standing_ids"`
	RequirementDigest     semantics.Digest  `json:"requirement_digest"`
	RequirementRoles      []string          `json:"requirement_roles"`
	RequirementVerdict    string            `json:"requirement_verdict"`
	NegativeErrors        map[string]string `json:"negative_errors"`
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func mustTime(s, what string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		fail("%s: %v", what, err)
	}
	return t
}

func errorCode(err error) string {
	if err == nil {
		return "none"
	}
	return strings.SplitN(err.Error(), ":", 2)[0]
}

func main() {
	capabilityDir := os.Getenv("CLC_CAPABILITY_DIR")
	if capabilityDir == "" {
		capabilityDir = "../capability"
	}
	path := filepath.Join(
		capabilityDir,
		"data/_vectors/clc-v1/extension-parity-vectors.json",
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		fail("parse fixture: %v", err)
	}

	record, err := semantics.RecordWithContext(
		[]semantics.Grant{f.Grant}, f.Operation, f.Context)
	if err != nil {
		fail("record: %v", err)
	}
	recordCanonical, err := record.CanonicalBytes()
	if err != nil {
		fail("record canonical bytes: %v", err)
	}

	contextDigest, err := f.Context.Digest()
	if err != nil {
		fail("context digest: %v", err)
	}

	actionDigest, err := semantics.DigestOf(f.ChallengeParams.ActionMaterial)
	if err != nil {
		fail("challenge action digest: %v", err)
	}
	challengeParams := semantics.ChallengeParams{
		ID:           f.ChallengeParams.ID,
		Nonce:        f.ChallengeParams.Nonce,
		Audience:     f.ChallengeParams.Audience,
		ActionDigest: actionDigest,
		Now:          mustTime(f.ChallengeParams.Now, "challenge now"),
		TTL:          time.Duration(f.ChallengeParams.TTLSeconds) * time.Second,
	}
	if f.ChallengeParams.RetryTiming != nil {
		challengeParams.Retry = &semantics.RetryTiming{
			NotBefore: mustTime(
				f.ChallengeParams.RetryTiming.NotBefore,
				"challenge retry not_before",
			),
			JitterSec: f.ChallengeParams.RetryTiming.JitterSec,
		}
	}
	challenge, err := semantics.BuildChallengeFromDecision(
		f.ChallengeDecision, challengeParams)
	if err != nil {
		fail("challenge: %v", err)
	}
	challengeDigest, err := challenge.Digest()
	if err != nil {
		fail("challenge digest: %v", err)
	}

	actionID, err := semantics.ComputeActionID(
		f.ActionDefinition, semantics.SuiteJCSSHA256, f.Action)
	if err != nil {
		fail("action id: %v", err)
	}

	envelope, err := semantics.NewEnvelope(record)
	if err != nil {
		fail("envelope: %v", err)
	}

	authorityDigest, err := semantics.DigestOf(
		f.SourceChain.AuthorityMaterial)
	if err != nil {
		fail("authority digest: %v", err)
	}
	artifactDigest, err := semantics.DigestOf(
		f.SourceChain.ArtifactMaterial)
	if err != nil {
		fail("artifact digest: %v", err)
	}
	chain := semantics.SourceChain{
		Sources: []semantics.SourceRef{
			{Kind: "authority", ID: "root", Digest: authorityDigest},
			{
				Kind:       "artifact",
				ID:         "child",
				Digest:     artifactDigest,
				References: []semantics.Digest{authorityDigest},
			},
		},
		Links: []semantics.SourceLink{
			{From: artifactDigest, To: authorityDigest},
		},
	}
	chainDigest, err := chain.Digest()
	if err != nil {
		fail("source chain digest: %v", err)
	}
	standing, err := chain.StandingOn(artifactDigest)
	if err != nil {
		fail("standing on: %v", err)
	}
	standingIDs := make([]string, 0, len(standing))
	for _, source := range standing {
		standingIDs = append(standingIDs, source.ID)
	}

	facts := make([]semantics.EvidenceFact, 0, len(f.Facts))
	for _, fact := range f.Facts {
		issuedAt := time.Time{}
		if fact.IssuedAt != "" {
			issuedAt = mustTime(fact.IssuedAt, "fact issued_at")
		}
		facts = append(facts, semantics.EvidenceFact{
			Type: fact.Type, Subject: fact.Subject,
			IssuedAt: issuedAt, Verified: fact.Verified,
		})
	}
	evidenceContext := semantics.EvidenceContext{
		Initiator: f.RequirementContext.Initiator,
		Executor:  f.RequirementContext.Executor,
	}
	if f.RequirementContext.Now != "" {
		evidenceContext.Now = mustTime(f.RequirementContext.Now, "requirement now")
	}
	requirementResult, err := semantics.EvaluateRequirement(
		f.Requirement, facts, evidenceContext)
	if err != nil {
		fail("requirement: %v", err)
	}
	requirementDigest, err := f.Requirement.Digest()
	if err != nil {
		fail("requirement digest: %v", err)
	}
	requirementRoles, err := f.Requirement.Roles()
	if err != nil {
		fail("requirement roles: %v", err)
	}

	missingDigest := record
	missingDigest.InputDigest = semantics.Digest{}
	tamperedRecord := record
	tamperedRecord.Verdict = semantics.VerdictDeny
	invalidRequirement := f.Requirement
	invalidRequirement.Expression = "approver & executor"
	negativeErrors := map[string]string{
		"context_stale": errorCode(f.Context.Fresh(
			mustTime("2026-10-19T12:02:00Z", "stale context instant"))),
		"record_missing_digest":   errorCode(missingDigest.Verify()),
		"record_tampered_verdict": errorCode(tamperedRecord.Verify()),
		"challenge_expired": errorCode(challenge.Usable(
			mustTime("2026-10-19T12:05:00Z", "expired challenge instant"))),
		"challenge_retry_not_before": errorCode(challenge.Usable(
			mustTime("2026-10-19T12:00:00Z", "early retry instant"))),
		"envelope_no_signature": errorCode(envelope.VerifyRecord(
			func(string, []byte, []byte) error { return nil })),
		"action_malformed": errorCode(func() error {
			_, parseErr := semantics.ParseActionId(
				"clc-action:1:payment.release:jcs-sha256:!!")
			return parseErr
		}()),
		"requirement_invalid_expression": errorCode(
			invalidRequirement.Validate()),
	}

	recordHash := sha256.Sum256(recordCanonical)
	envelopeHash := sha256.Sum256(envelope.Payload)
	got := output{
		RecordCanonicalSHA256: fmt.Sprintf("%x", recordHash),
		ContextDigest:         contextDigest,
		ChallengeDigest:       challengeDigest,
		ActionID:              actionID.String(),
		EnvelopePayloadSHA256: fmt.Sprintf("%x", envelopeHash),
		SourceChainDigest:     chainDigest,
		StandingIDs:           standingIDs,
		RequirementDigest:     requirementDigest,
		RequirementRoles:      requirementRoles,
		RequirementVerdict:    string(requirementResult.Verdict),
		NegativeErrors:        negativeErrors,
	}

	gotCanonical, err := semantics.CanonicalJSON(got)
	if err != nil {
		fail("canonical output: %v", err)
	}
	wantCanonical, err := semantics.CanonicalJSON(f.Expect)
	if err != nil {
		fail("canonical expected: %v", err)
	}
	if string(gotCanonical) != string(wantCanonical) {
		fail("parity mismatch\nexpected %s\ngot      %s", wantCanonical, gotCanonical)
	}
	fmt.Println(string(gotCanonical))
}
