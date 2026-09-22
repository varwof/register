// Command authorize-chain-vectors-run reads the CLC-D §13.11
// AuthorizeWithChain vectors (rev CLC-1.13) and runs them against the
// semantics package.
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
	ID               string               `json:"id"`
	Kind             string               `json:"kind"`
	SpecClause       string               `json:"spec_clause"`
	CLCRevision      string               `json:"clc_revision"`
	ConformanceClass string               `json:"conformance_class"`
	Chain            []semantics.Grant    `json:"chain"`
	Request          *semantics.Operation `json:"request"`
	Expect           Expectation          `json:"expect"`
	Derivation       string               `json:"derivation"`
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
	path := os.Getenv("CLC_AUTHORIZE_CHAIN_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-d/authorize-chain-vectors.json"
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
	for _, v := range vectors {
		op := semantics.Operation{}
		if v.Request != nil {
			op = *v.Request
		}
		got := semantics.AuthorizeWithChain(v.Chain, op)
		expReason := canonicalReason(v.Expect.Reason)
		gotReason := canonicalReason(got.Reason)
		ok := got.Verdict == v.Expect.Verdict && gotReason == expReason
		if ok && v.Expect.Unresolved != nil {
			ok = slices.Equal(got.Unresolved, v.Expect.Unresolved)
		}
		if ok {
			pass++
		} else {
			fail++
			fmt.Printf("%-8s FAIL want=%s/%s/%v got=%s/%s/%v\n", v.ID, v.Expect.Verdict, expReason, v.Expect.Unresolved, got.Verdict, gotReason, got.Unresolved)
		}
	}
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}
