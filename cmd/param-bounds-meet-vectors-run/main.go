// Command param-bounds-meet-vectors-run reads the CLC-v1 §6.6 BoundMeet
// vectors (rev CLC-1.14) and runs them against the semantics package.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/varwof/register/semantics"
)

type Vector struct {
	ID               string                 `json:"id"`
	Kind             string                 `json:"kind"`
	SpecClause       string                 `json:"spec_clause"`
	CLCRevision      string                 `json:"clc_revision"`
	ConformanceClass string                 `json:"conformance_class"`
	Sources          []semantics.Grant      `json:"sources"`
	Expect           map[string]interface{} `json:"expect"`
	Derivation       string                 `json:"derivation"`
}

func canonicalReason(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

func main() {
	path := os.Getenv("CLC_PARAM_BOUNDS_MEET_VECTORS")
	if path == "" {
		path = "../capability/data/_vectors/clc-v1/param-bounds-meet-vectors.json"
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
		ok, detail := run(v)
		if ok {
			pass++
			continue
		}
		fail++
		fmt.Printf("%-8s FAIL %s\n", v.ID, detail)
	}
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(vectors), pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func run(v Vector) (bool, string) {
	got, err := semantics.Intersect(v.Sources...)
	if wantReason, hasReason := v.Expect["reason"]; hasReason {
		if err == nil {
			return false, fmt.Sprintf("want reason %v, got success", wantReason)
		}
		gotReason := canonicalReason(err.Error())
		if gotReason != wantReason {
			return false, fmt.Sprintf("want reason %v, got %q", wantReason, gotReason)
		}
		return true, ""
	}
	if err != nil {
		return false, fmt.Sprintf("unexpected error %v", err)
	}
	if wantPB, ok := v.Expect["param_bounds"]; ok {
		if !reflect.DeepEqual(asMap(got.ParamBounds), asMap(wantPB)) {
			return false, fmt.Sprintf("param_bounds = %v, want %v", got.ParamBounds, wantPB)
		}
	} else if len(got.ParamBounds) != 0 {
		return false, fmt.Sprintf("unexpected param_bounds %v", got.ParamBounds)
	}
	if wantParams, ok := v.Expect["params"]; ok {
		if !reflect.DeepEqual(asMap(got.Params), asMap(wantParams)) {
			return false, fmt.Sprintf("params = %v, want %v", got.Params, wantParams)
		}
	} else if len(got.Params) != 0 {
		return false, fmt.Sprintf("unexpected params %v", got.Params)
	}
	return true, ""
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}
