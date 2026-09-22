// Command resolve-vectors-run reads the CLC-v1 §8.5 Resolve vectors
// (rev CLC-1.11) and runs them against the semantics package.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/varwof/register/semantics"
)

type Vector struct {
	ID               string                 `json:"id"`
	Kind             string                 `json:"kind"`
	SpecClause       string                 `json:"spec_clause"`
	CLCRevision      string                 `json:"clc_revision"`
	ConformanceClass string                 `json:"conformance_class"`
	Decision         semantics.Decision     `json:"decision"`
	Resolutions      []semantics.Resolution `json:"resolutions"`
	Now              string                 `json:"now,omitempty"`
	Expect           Expectation            `json:"expect"`
	Derivation       string                 `json:"derivation"`
}

type Expectation struct {
	Verdict    string   `json:"verdict"`
	Reason     string   `json:"reason,omitempty"`
	Unresolved []string `json:"unresolved"`
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
	path := os.Getenv("CLC_RESOLVE_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-v1/resolve-vectors.json"
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
	fmt.Printf("%-12s %-10s %-24s %-24s %s\n", "ID", "GOT", "EXP-REASON", "GOT-REASON", "RESULT")
	fmt.Println(strings.Repeat("-", 96))
	for _, v := range vectors {
		got := semantics.Resolve(v.Decision, v.Resolutions, v.Now)
		expReason := canonicalReason(v.Expect.Reason)
		gotReason := canonicalReason(got.Reason)
		ok := got.Verdict == v.Expect.Verdict && gotReason == expReason
		if ok && v.Expect.Unresolved != nil {
			ok = slices.Equal(got.Unresolved, v.Expect.Unresolved)
		}
		status := "PASS"
		if !ok {
			status = fmt.Sprintf("FAIL (got unresolved %v)", got.Unresolved)
			fail++
		} else {
			pass++
		}
		fmt.Printf("%-12s %-10s %-24s %-24s %s\n", v.ID, got.Verdict, expReason, gotReason, status)
	}
	fmt.Println(strings.Repeat("-", 96))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}
