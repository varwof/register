// Command param-bounds-vectors-run reads the CLC-v1 §6.5 extended parameter
// bound vectors (rev CLC-1.10) and runs them against the semantics package.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/semantics"
)

type Vector struct {
	ID               string               `json:"id"`
	Kind             string               `json:"kind"`
	SpecClause       string               `json:"spec_clause"`
	CLCRevision      string               `json:"clc_revision"`
	ConformanceClass string               `json:"conformance_class"`
	Grant            *semantics.Grant     `json:"grant"`
	Request          *semantics.Operation `json:"request"`
	SchemeDefaults   map[string]any       `json:"scheme_defaults,omitempty"`
	Expect           Expectation          `json:"expect"`
	Derivation       string               `json:"derivation"`
}

type Expectation struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

func canonicalReason(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

func main() {
	path := os.Getenv("CLC_PARAM_BOUNDS_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-v1/param-bounds-vectors.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading vectors: %v\n", err)
		os.Exit(1)
	}
	var vectors []Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vectors: %v\n", err)
		os.Exit(1)
	}

	pass, fail := 0, 0
	fmt.Printf("%-10s %-14s %-10s %-24s %-24s %s\n", "ID", "KIND", "GOT", "EXP-REASON", "GOT-REASON", "RESULT")
	fmt.Println(strings.Repeat("-", 96))
	for _, v := range vectors {
		got, reason := run(v)
		expReason := canonicalReason(v.Expect.Reason)
		ok := got == v.Expect.Verdict && reason == expReason
		status := "PASS"
		if !ok {
			status = "FAIL"
			fail++
		} else {
			pass++
		}
		fmt.Printf("%-10s %-14s %-10s %-24s %-24s %s\n", v.ID, v.Kind, got, expReason, reason, status)
	}
	fmt.Println(strings.Repeat("-", 96))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func run(v Vector) (string, string) {
	grant := semantics.Grant{}
	if v.Grant != nil {
		grant = *v.Grant
	}
	op := semantics.Operation{}
	if v.Request != nil {
		op = *v.Request
	}
	if v.Kind == "param-defaults" {
		op = semantics.MaterializeDefaults(grant, op, v.SchemeDefaults)
	}
	res := semantics.Entails(grant, op)
	if res.Entails {
		return "allow", ""
	}
	return "deny", canonicalReason(res.Reason)
}
