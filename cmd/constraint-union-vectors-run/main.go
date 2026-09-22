// Command constraint-union-vectors-run reads the CLC-v1 §7.1 ConstraintUnion
// vectors (rev CLC-1.12) and runs them against the semantics package.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/varwof/register/semantics"
)

type Vector struct {
	ID               string            `json:"id"`
	Kind             string            `json:"kind"`
	SpecClause       string            `json:"spec_clause"`
	CLCRevision      string            `json:"clc_revision"`
	ConformanceClass string            `json:"conformance_class"`
	Chain            []semantics.Grant `json:"chain"`
	Expect           Expectation       `json:"expect"`
	Derivation       string            `json:"derivation"`
}

type Expectation struct {
	Union  []string `json:"union"`
	Reason string   `json:"reason,omitempty"`
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
	path := os.Getenv("CLC_CONSTRAINT_UNION_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-v1/constraint-union-vectors.json"
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
		got, err := semantics.ConstraintUnion(v.Chain...)
		ok := true
		detail := ""
		if v.Expect.Reason != "" {
			ok = errors.Is(err, semantics.ErrAbsentSource) && canonicalReason(errString(err)) == canonicalReason(v.Expect.Reason)
			detail = fmt.Sprintf("got err=%v", err)
		} else {
			ok = err == nil && slices.Equal(got, v.Expect.Union)
			detail = fmt.Sprintf("got=%v", got)
		}
		if ok {
			pass++
		} else {
			fail++
			fmt.Printf("%-8s FAIL want=%v/%s %s\n", v.ID, v.Expect.Union, v.Expect.Reason, detail)
		}
	}
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
