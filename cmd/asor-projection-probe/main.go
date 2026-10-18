// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command asor-projection-probe projects an ASOR delegation chain
// (draft-asor-wimse-agent-delegation-chain-02) onto CLC grants and runs the
// chain authorization.
//
// It mirrors the evidence-side probes: map the carrier's native structure into
// CLC, evaluate, and report what the mapping could not carry.  ASOR's own
// verification is an eight-step algorithm (§6); this probe covers the steps CLC
// can decide (scope and constraint subset) and names the ones it cannot.
//
// Fields checked against ASOR-02 §4.1 (scope syntax), §4.2 (constraint
// vocabulary), §3 (par_hash, del_depth) on 2026-10-17.
package main

import (
	"fmt"
	"strings"

	"github.com/varwof/register/semantics"
)

// scopeScheme is the CLC scheme a carved ASOR scope is mapped into.
const scopeScheme = "asor/agent-delegation-v1"

type constraint struct {
	Key  string
	Max  *float64
	Enum []string
	Kind string // the type member, for residuals (max_lifetime, rank, ...)
}

type dt struct {
	Name        string
	Scopes      []string
	Constraints []constraint
}

// toGrants maps one ASOR token: one CLC grant per scope, sharing the token's
// constraints as params.
func toGrants(d dt) ([]semantics.Grant, []string) {
	params := map[string]any{}
	var residual []string
	for _, c := range d.Constraints {
		switch {
		case c.Max != nil:
			params[c.Key] = *c.Max
		case len(c.Enum) > 0:
			vals := make([]any, 0, len(c.Enum))
			for _, v := range c.Enum {
				vals = append(vals, v)
			}
			params[c.Key] = vals
		default:
			residual = append(residual, fmt.Sprintf("%s: constraint %q (%s) has no CLC param form",
				d.Name, c.Key, c.Kind))
		}
	}
	grants := make([]semantics.Grant, 0, len(d.Scopes))
	for _, s := range d.Scopes {
		id := scopeScheme + ":" + strings.ReplaceAll(s, ".", ":")
		p := make(map[string]any, len(params))
		for k, v := range params {
			p[k] = v
		}
		grants = append(grants, semantics.Grant{ID: id, Params: p})
	}
	return grants, residual
}

func covers(grantID, opID string) bool {
	if strings.HasSuffix(grantID, "*") {
		return strings.HasPrefix(opID, strings.TrimSuffix(grantID, "*"))
	}
	return grantID == opID
}

func f(v float64) *float64 { return &v }

func main() {
	root := dt{
		Name:        "DT_0",
		Scopes:      []string{"crm.customer.read", "crm.customer.write", "crm.*"},
		Constraints: []constraint{{Key: "max_rows", Max: f(5000)}},
	}
	leaf := dt{
		Name:        "DT_1",
		Scopes:      []string{"crm.customer.read"},
		Constraints: []constraint{{Key: "max_rows", Max: f(3000)}},
	}

	fmt.Println("ASOR delegation chain → CLC authorization projection")
	fmt.Println("Fields: draft-asor-wimse-agent-delegation-chain-02 §3/§4.1/§4.2 (checked 2026-10-17)")
	fmt.Println()

	rootGrants, rootRes := toGrants(root)
	leafGrants, leafRes := toGrants(leaf)
	fmt.Println("1. Mapping")
	for _, g := range rootGrants {
		fmt.Printf("   %-30s params=%v\n", g.ID, g.Params)
	}
	for _, g := range leafGrants {
		fmt.Printf("   %-30s params=%v\n", g.ID, g.Params)
	}
	for _, r := range append(rootRes, leafRes...) {
		fmt.Println("   residual: " + r)
	}
	for _, r := range []string{
		"par_hash: chain linkage, carrier-only (ASOR §5)",
		"del_depth / del_max_depth: chain shape, carrier-only (§3)",
		"delegation_mode: carrier pre-check (§13.4.5 in CLC terms)",
		"sub / principal standing at use: outside the chain (§9.7)",
		"status / revocation: outside the chain (fail-closed carrier step)",
	} {
		fmt.Println("   residual: " + r)
	}
	fmt.Println()

	fmt.Println("2. Set containment (every leaf grant inside some root grant)")
	for _, cg := range leafGrants {
		ok := false
		reason := ""
		for _, pg := range rootGrants {
			if r := semantics.Contains(pg, cg); r.Contains {
				ok = true
				break
			} else if reason == "" && r.Reason != "" {
				reason = r.Reason
			}
		}
		if ok {
			reason = "contained"
		} else if reason == "" {
			reason = "no parent grant covers the identifier"
		}
		fmt.Printf("   %-30s contains=%v (%s)\n", cg.ID, ok, reason)
	}
	fmt.Println()

	fmt.Println("3. Chain authorization for an operation")
	cases := []struct {
		name string
		id   string
		rows float64
		want string
	}{
		{"read, max_rows 2000 (inside leaf)", scopeScheme + ":crm:customer:read", 2000, "allow"},
		{"read, max_rows 3000 (at leaf bound)", scopeScheme + ":crm:customer:read", 3000, "allow"},
		{"read, max_rows 3001 (above leaf)", scopeScheme + ":crm:customer:read", 3001, "deny"},
		{"write (root only, leaf lacks it)", scopeScheme + ":crm:customer:write", 1000, "no-chain"},
	}
	for _, c := range cases {
		chain, ok := selectChain([]dt{root, leaf}, [][]semantics.Grant{rootGrants, leafGrants}, c.id)
		got := "no-chain"
		if ok {
			dec := semantics.AuthorizeWithChain(chain, semantics.Operation{
				ID: c.id, Params: map[string]any{"max_rows": c.rows},
			})
			got = dec.Verdict
			if dec.Reason != "" {
				got += "/" + dec.Reason
			}
		}
		status := "PASS"
		if !strings.HasPrefix(got, c.want) {
			status = "FAIL"
		}
		fmt.Printf("   %-38s want %-8s got %-28s %s\n", c.name, c.want, got, status)
	}
	fmt.Println()
	fmt.Println("Reading: CLC decides the scope/constraint subset steps; par_hash, depth,")
	fmt.Println("mode, standing and status stay with the carrier.  Note that one ASOR token")
	fmt.Println("maps to *several* CLC grants (one per scope), so a chain is selected per")
	fmt.Println("operation — a mapping rule the binding profile has to state.")
}

// selectChain picks, for each hop, the first grant that covers the operation id.
func selectChain(hops []dt, grants [][]semantics.Grant, opID string) ([]semantics.Grant, bool) {
	chain := make([]semantics.Grant, 0, len(grants))
	for _, gs := range grants {
		found := false
		for _, g := range gs {
			if covers(g.ID, opID) {
				chain = append(chain, g)
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return chain, true
}
