// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command rar-projection-probe projects OAuth Rich Authorization Requests
// (RFC 9396 authorization_details) onto CLC grants and evaluates operations.
//
// It is the second authorization-side probe, alongside the ASOR one.  RAR is
// the carriage every OAuth profile starts from, so the question is which RAR
// members have a CLC slot, which become several grants, and which have none.
//
// Members checked against RFC 9396 §2 (type, locations, actions, datatypes,
// identifier) and the payment example in §3 on 2026-10-17.
package main

import (
	"fmt"
	"sort"

	"github.com/varwof/register/semantics"
)

const scheme = "oauth-rar/rar-v1"

// detail is one authorization_details entry.
type detail struct {
	Type       string
	Actions    []string
	Amount     *float64
	Currency   string
	Identifier string
	Locations  []string
	Datatypes  []string
}

func f(v float64) *float64 { return &v }

// toGrants maps one detail: one CLC grant per action, type-specific fields as
// params.
func toGrants(d detail) ([]semantics.Grant, []string) {
	params := map[string]any{}
	var residual []string
	if d.Amount != nil {
		params["amount"] = *d.Amount
	}
	if d.Currency != "" {
		params["currency"] = []any{d.Currency}
	}
	if d.Identifier != "" {
		params["identifier"] = []any{d.Identifier}
	}
	if len(d.Locations) > 0 {
		residual = append(residual, fmt.Sprintf(
			"locations %v: a where-it-may-be-used constraint has no CLC slot", d.Locations))
	}
	if len(d.Datatypes) > 0 {
		residual = append(residual, fmt.Sprintf(
			"datatypes %v: constrains the resource's data, not the operation", d.Datatypes))
	}
	grants := make([]semantics.Grant, 0, len(d.Actions))
	for _, a := range d.Actions {
		p := make(map[string]any, len(params))
		for k, v := range params {
			p[k] = v
		}
		grants = append(grants, semantics.Grant{ID: scheme + ":" + d.Type + ":" + a, Params: p})
	}
	return grants, residual
}

func main() {
	d := detail{
		Type:       "payment",
		Actions:    []string{"transfer", "refund"},
		Amount:     f(5000),
		Currency:   "CNY",
		Identifier: "acct-1234",
		Locations:  []string{"https://api.bank.example"},
	}
	grants, residual := toGrants(d)

	fmt.Println("OAuth RAR authorization_details → CLC grants")
	fmt.Println("Members: RFC 9396 §2/§3 (checked 2026-10-17)")
	fmt.Println()
	fmt.Println("1. Mapping")
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.ID)
	}
	sort.Strings(ids)
	for _, g := range grants {
		fmt.Printf("   %-36s params=%v\n", g.ID, g.Params)
	}
	for _, r := range residual {
		fmt.Println("   residual: " + r)
	}
	fmt.Println()

	fmt.Println("2. Operations")
	cases := []struct {
		caseID string
		name   string
		id     string
		amount float64
		cur    string
		want   string
	}{
		{"RAR-001", "transfer 3000 CNY", scheme + ":payment:transfer", 3000, "CNY", "allow"},
		{"RAR-002", "transfer 6000 CNY (above bound)", scheme + ":payment:transfer", 6000, "CNY", "deny/params_exceed_grant"},
		{"RAR-003", "transfer 3000 USD (not the enum)", scheme + ":payment:transfer", 3000, "USD", "deny/not_in_enum"},
		{"RAR-004", "refund 1000 CNY (second action)", scheme + ":payment:refund", 1000, "CNY", "allow"},
	}
	for _, c := range cases {
		op := semantics.Operation{ID: c.id, Params: map[string]any{
			"amount": c.amount, "currency": c.cur, "identifier": "acct-1234",
		}}
		var dec semantics.Decision
		for _, g := range grants {
			if g.ID == c.id {
				dec = semantics.AuthorizeSet([]semantics.Grant{g}, op)
				break
			}
		}
		got := dec.Verdict
		if dec.Reason != "" {
			got += "/" + dec.Reason
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-36s want=%s got=%s\n", status, c.caseID, c.name, c.want, got)
	}
	fmt.Println()
	fmt.Println("Reading: actions multiply into grants, type-specific fields become params,")
	fmt.Println("and `locations` has no CLC slot.  A binding profile must state both the")
	fmt.Println("type→scheme naming rule and what happens to locations (carrier-enforced).")
}
