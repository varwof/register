// Command contains-vectors-run reads CLC-D containment vectors
// (draft-wei-clc-ext-00 §7) and runs them against semantics.Contains.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/semantics"
)

type Grant = semantics.Grant

type Vector struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	SpecClause       string `json:"spec_clause"`
	ExtRevision      string `json:"ext_revision"`
	ConformanceClass string `json:"conformance_class"`
	Parent           Grant  `json:"parent"`
	Child            Grant  `json:"child"`
	Expect           struct {
		Contains bool   `json:"contains"`
		Reason   string `json:"reason"`
	} `json:"expect"`
	Derivation string `json:"derivation"`
}

func canonicalReason(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

func main() {
	path := os.Getenv("CLC_D_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-d/containment-vectors.json"
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

	pass := 0
	fail := 0
	for _, v := range vectors {
		r := semantics.Contains(v.Parent, v.Child)
		gotContains := r.Entails
		gotReason := canonicalReason(r.Reason)
		ok := gotContains == v.Expect.Contains &&
			(v.Expect.Contains || len(v.Expect.Reason) == 0 || gotReason == v.Expect.Reason)
		if ok {
			pass++
			fmt.Printf("%-14s contains=%-5v reason=%-24s derivation=%s\n",
				v.ID, gotContains, gotReason, v.Derivation)
		} else {
			fail++
			fmt.Printf("%-14s FAIL  want.contains=%-5v want.reason=%s got.contains=%-5v got.reason=%s derivation=%s\n",
				v.ID, v.Expect.Contains, v.Expect.Reason, gotContains, gotReason, v.Derivation)
		}
	}
	fmt.Printf("\nTotal: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}
