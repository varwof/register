// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command oasnt-projection-probe projects an OASNT approval token
// (draft-thallapelly-oasnt-02) onto the CLC evidence projection.
//
// OASNT is a third, independent evidence source: a human approval token bound
// to a flat canonical action (adg), a disclosure digest (dsp), an optional
// request fingerprint (rqf), a single-use nonce (jti), and a device integrity
// result (int).  The probe asks which of those become a CLC fact or observation,
// which are the enforcement point's business, and which have no CLC axis.
//
// Checked against draft-thallapelly-oasnt-02 §5.3 (claims) and §6.2 (canonical
// action) on 2026-10-17.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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

type token struct {
	Sub string
	ADG string
	Int string // clean | compromised | unknown
}

func main() {
	typ := "payments.transfer"
	approved := map[string]string{"amount": "3000", "currency": "CNY"}
	tk := token{Sub: "user:alice@example.org", ADG: adg(typ, approved), Int: "clean"}

	fmt.Println("OASNT approval → CLC evidence projection")
	fmt.Println("Fields: draft-thallapelly-oasnt-02 §5.3/§6.2 (checked 2026-10-17)")
	fmt.Println()
	fmt.Printf("canonical action: %s\n", canonicalAction(typ, approved))
	fmt.Printf("adg: %s\n\n", tk.ADG)

	fmt.Println("1. Action binding (adg) against the presented action")
	for _, c := range []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"same action", approved, "MATCH"},
		{"amount 3001", map[string]string{"amount": "3001", "currency": "CNY"}, "NOT_EQUIVALENT"},
		{"extra parameter added", map[string]string{"amount": "3000", "currency": "CNY", "memo": "x"}, "NOT_EQUIVALENT"},
	} {
		got := "NOT_EQUIVALENT"
		if adg(typ, c.params) == tk.ADG {
			got = "MATCH"
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("   %-28s want %-15s got %-15s %s\n", c.name, c.want, got, status)
	}
	fmt.Println()

	fmt.Println("2. Approval as a CLC fact (§10 requirement over one role)")
	req := map[string]any{
		"@version":       "CLC-REQUIREMENT-v1",
		"requirement_id": "oasnt-approval@1",
		"expression":     "human-authorization",
		"constraints": []map[string]string{
			{"role": "human-authorization", "constraint": "varwof/evidence-v1:freshness:sec:300"},
		},
	}
	raw, _ := json.Marshal(req)
	parsed, err := semantics.ParseRequirement(raw)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		verified bool
		ago      time.Duration
		want     string
	}{
		{"int=clean, approved 30s ago", true, 30 * time.Second, "SATISFIED"},
		{"int=compromised (not eligible)", false, 30 * time.Second, "UNSATISFIED"},
		{"approved 301s ago", true, 301 * time.Second, "UNSATISFIED"},
	} {
		facts := []semantics.EvidenceFact{{
			Type: "human-authorization", Subject: tk.Sub, Verified: c.verified,
			IssuedAt: now.Add(-c.ago),
		}}
		res, err := semantics.EvaluateRequirement(parsed, facts, semantics.EvidenceContext{Now: now})
		got := "error"
		if err == nil {
			got = string(res.Satisfaction().Verdict)
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("   %-32s want %-11s got %-11s %s\n", c.name, c.want, got, status)
	}
	fmt.Println()

	fmt.Println("3. Members with no CLC axis (residual, carrier or enforcement point)")
	for _, r := range []string{
		"dsp: what the human read; CLC has no disclosure axis",
		"rqf: one concrete request; CLC identity is the action, not the request instance",
		"asl: assurance level; carrier-owned",
		"int: device integrity; only its effect on eligibility is expressible (verified)",
		"jti: single-use nonce; consumption is the enforcement point's (AEB/BCR)",
		"exp: validity deadline, not an age bound; CLC freshness is age-based",
		"nested parameters: the canonical action is flat; nested args need a mapping",
	} {
		fmt.Println("   - " + r)
	}
	fmt.Println()
	fmt.Println("Reading: OASNT projects cleanly onto one Fact plus an action binding; the")
	fmt.Println("rest are carrier or enforcement members.  The relation-shaped gap does not")
	fmt.Println("appear here because OASNT binds approval to an action by identity, not by a")
	fmt.Println("relation between two evidence artifacts.")
}
