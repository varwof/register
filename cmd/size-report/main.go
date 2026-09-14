// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command size-report prints the byte budget of the evidence artifacts this
// module produces, so a change to a record, envelope or challenge shape can be
// compared against the numbers recorded in the wire-size budget note that
// accompanies the language revision (capability `docs/`), so the figures stay
// reviewable next to the specification they belong to.
//
// The inputs are fixed samples, not a benchmark: the point is a stable,
// reproducible figure for "how much does one decision cost on the wire".
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/register/semantics"
)

// sampleConstraint is a representative authorization constraint (one UTC window).
const sampleConstraint = `varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`

func dg(s string) semantics.Digest {
	sum := sha256.Sum256([]byte(s))
	return semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: sum[:]}
}

func main() {
	grant := semantics.Grant{ID: "varwof/demo-mysql-v1:SELECT:*", Constraints: []string{sampleConstraint}}
	op := semantics.Operation{ID: "varwof/demo-mysql-v1:SELECT:*"}

	fmt.Println("constraint strings (the only variable-length part of a capability)")
	for _, c := range []struct {
		name       string
		constraint string
	}{
		{"max_rows", `varwof/constraint-v1:max_rows:100`},
		{"time one window", sampleConstraint},
		{"time 32 windows", `varwof/constraint-v1:time:window:[` + windows(32) + `]`},
		{"network one cidr", `varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`},
		{"network 32 cidr", `varwof/constraint-v1:network:cidr:[` + cidrs(32) + `]`},
		{"evidence quorum", `varwof/evidence-v1:quorum:distinct:2`},
	} {
		fmt.Printf("  %-18s %5d B\n", c.name, len(c.constraint))
	}

	plain, err := semantics.Record([]semantics.Grant{grant}, op)
	if err != nil {
		panic(err)
	}
	plainBytes, err := plain.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("record (bare)                    %5d B\n", len(plainBytes))

	principal, da, aic := dg("principal-cert-der"), dg("delegation-authorization"), dg("aic-cert-der")
	chain := &semantics.SourceChain{
		Sources: []semantics.SourceRef{
			{Kind: "principal-cert", ID: "people-user01:1", Issuer: "People CA", Digest: principal},
			{Kind: "delegation", ID: "da:v2:nonce-1", Issuer: "people-user01", Digest: da, References: []semantics.Digest{principal}},
			{Kind: "aic-x509", ID: "serial:7f3a", Issuer: "People CA", Digest: aic, References: []semantics.Digest{da}},
		},
		Links: []semantics.SourceLink{{From: aic, To: da}, {From: da, To: principal}},
	}
	snapshot := dg("trust-snapshot")
	ctx := semantics.DecisionContext{At: time.Now().UTC().Truncate(time.Second), MaxAgeSec: 60, SnapshotDigest: &snapshot}
	req := semantics.Requirement{
		Version:     semantics.RequirementVersion,
		ID:          "wire-release-evidence@7",
		Expression:  "human-authorization AND policy-permit",
		Constraints: []semantics.RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:quorum:distinct:2"}},
	}
	full, err := semantics.RecordWith([]semantics.Grant{grant}, op,
		semantics.RecordOptions{Context: &ctx, Sources: chain, Requirement: &req})
	if err != nil {
		panic(err)
	}
	fullBytes, err := full.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("record (+context+sources+req)    %5d B\n", len(fullBytes))

	env, err := semantics.NewEnvelope(full)
	if err != nil {
		panic(err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("DSSE/in-toto envelope            %5d B\n", len(envBytes))

	decision := semantics.Authorize(semantics.Grant{ID: grant.ID, Constraints: []string{sampleConstraint}}, op)
	challenge, err := semantics.BuildChallengeFromDecision(decision, semantics.ChallengeParams{
		ID:           "ch_01H",
		Nonce:        "nonce-0123456789",
		Audience:     "https://gateway-a.example",
		ActionDigest: dg("the-action"),
		Now:          time.Now().UTC(),
		TTL:          5 * time.Minute,
		ObtainHints:  []semantics.ObtainHint{{ID: "varwof/constraint-v1:time", Mechanism: "varwof/time-window-v1"}},
	})
	if err != nil {
		panic(err)
	}
	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		panic(err)
	}
	fmt.Printf("challenge CLC-CHALLENGE-v1       %5d B\n", len(challengeBytes))

	problem := struct {
		Type      string               `json:"type"`
		Title     string               `json:"title"`
		Status    int                  `json:"status"`
		Detail    string               `json:"detail"`
		Challenge *semantics.Challenge `json:"challenge"`
	}{
		Type:      "https://varwof.com/clc/v1/problems/evidence-required",
		Title:     "Authorization evidence required",
		Status:    403,
		Detail:    "operation needs a confirmed time window",
		Challenge: &challenge,
	}
	problemBytes, err := json.Marshal(problem)
	if err != nil {
		panic(err)
	}
	fmt.Printf("problem+json body                %5d B\n", len(problemBytes))
}

func windows(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"start":"%02d:00","end":"%02d:30"}`, i, i)
	}
	return out
}

func cidrs(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`"10.%d.0.0/16"`, i)
	}
	return out
}
