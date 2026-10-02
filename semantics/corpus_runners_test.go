// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// The per-kind corpora run through standalone `cmd/*-vectors-run` programs.
// These tests mirror them inside the package so `go test ./...` exercises the
// resolve, param-bounds, param-bounds-meet, constraint-union, containment and
// authorize-chain surface without invoking a binary.  Each subtest fails with
// the vector id and the mismatching field.

func corpusPath(env, defaultRel string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	return filepath.Join("..", "..", "capability", "data", "_vectors", filepath.FromSlash(defaultRel))
}

func loadCorpus(t *testing.T, env, rel string, out any) {
	t.Helper()
	path := corpusPath(env, rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("corpus not found at %s: %v", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func TestResolveVectorsCorpus(t *testing.T) {
	var vectors []struct {
		ID          string       `json:"id"`
		Decision    Decision     `json:"decision"`
		Resolutions []Resolution `json:"resolutions"`
		Now         string       `json:"now"`
		Expect      struct {
			Verdict    string   `json:"verdict"`
			Reason     string   `json:"reason"`
			Unresolved []string `json:"unresolved"`
		} `json:"expect"`
	}
	loadCorpus(t, "CLC_RESOLVE_VECTORS", "clc-v1/resolve-vectors.json", &vectors)

	for _, v := range vectors {
		got := Resolve(v.Decision, v.Resolutions, v.Now)
		if got.Verdict != v.Expect.Verdict || canonicalCode(got.Reason) != canonicalCode(v.Expect.Reason) {
			t.Errorf("%s: want %s/%s, got %s/%s", v.ID, v.Expect.Verdict,
				canonicalCode(v.Expect.Reason), got.Verdict, canonicalCode(got.Reason))
			continue
		}
		if v.Expect.Unresolved != nil && !slices.Equal(got.Unresolved, v.Expect.Unresolved) {
			t.Errorf("%s: unresolved want %v, got %v", v.ID, v.Expect.Unresolved, got.Unresolved)
		}
	}
}

func TestParamBoundsVectorsCorpus(t *testing.T) {
	var vectors []struct {
		ID             string         `json:"id"`
		Kind           string         `json:"kind"`
		Grant          *Grant         `json:"grant"`
		Request        *Operation     `json:"request"`
		SchemeDefaults map[string]any `json:"scheme_defaults"`
		Expect         struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
		} `json:"expect"`
	}
	loadCorpus(t, "CLC_PARAM_BOUNDS_VECTORS", "clc-v1/param-bounds-vectors.json", &vectors)

	for _, v := range vectors {
		grant := Grant{}
		if v.Grant != nil {
			grant = *v.Grant
		}
		op := Operation{}
		if v.Request != nil {
			op = *v.Request
		}
		if v.Kind == "param-defaults" {
			op = MaterializeDefaults(grant, op, v.SchemeDefaults)
		}
		res := Entails(grant, op)
		got, reason := "deny", canonicalCode(res.Reason)
		if res.Entails {
			got, reason = "allow", ""
		}
		if got != v.Expect.Verdict || reason != canonicalCode(v.Expect.Reason) {
			t.Errorf("%s (%s): want %s/%s, got %s/%s", v.ID, v.Kind, v.Expect.Verdict,
				canonicalCode(v.Expect.Reason), got, reason)
		}
	}
}

func TestParamBoundsMeetVectorsCorpus(t *testing.T) {
	var vectors []struct {
		ID      string         `json:"id"`
		Sources []Grant        `json:"sources"`
		Expect  map[string]any `json:"expect"`
	}
	loadCorpus(t, "CLC_PARAM_BOUNDS_MEET_VECTORS", "clc-v1/param-bounds-meet-vectors.json", &vectors)

	for _, v := range vectors {
		got, err := Intersect(v.Sources...)
		if wantReason, has := v.Expect["reason"]; has {
			if err == nil || canonicalCode(err.Error()) != wantReason {
				t.Errorf("%s: want reason %v, got %v", v.ID, wantReason, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", v.ID, err)
			continue
		}
		if wantPB, ok := v.Expect["param_bounds"]; ok {
			if !reflect.DeepEqual(map[string]any(got.ParamBounds), toMap(wantPB)) {
				t.Errorf("%s: param_bounds %v, want %v", v.ID, got.ParamBounds, wantPB)
			}
		} else if len(got.ParamBounds) != 0 {
			t.Errorf("%s: unexpected param_bounds %v", v.ID, got.ParamBounds)
		}
		if wantParams, ok := v.Expect["params"]; ok {
			if !reflect.DeepEqual(map[string]any(got.Params), toMap(wantParams)) {
				t.Errorf("%s: params %v, want %v", v.ID, got.Params, wantParams)
			}
		} else if len(got.Params) != 0 {
			t.Errorf("%s: unexpected params %v", v.ID, got.Params)
		}
	}
}

func toMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func TestConstraintUnionVectorsCorpus(t *testing.T) {
	testConstraintUnionCorpus(t, "CLC_CONSTRAINT_UNION_VECTORS", "clc-v1/constraint-union-vectors.json")
}

func testConstraintUnionCorpus(t *testing.T, env, rel string) {
	t.Helper()
	var vectors []struct {
		ID     string  `json:"id"`
		Chain  []Grant `json:"chain"`
		Expect struct {
			Union  []string `json:"union"`
			Reason string   `json:"reason"`
		} `json:"expect"`
	}
	loadCorpus(t, env, rel, &vectors)

	for _, v := range vectors {
		got, err := ConstraintUnion(v.Chain...)
		if v.Expect.Reason != "" {
			if err == nil || canonicalCode(err.Error()) != canonicalCode(v.Expect.Reason) {
				t.Errorf("%s: want reason %q, got %v", v.ID, v.Expect.Reason, err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, v.Expect.Union) {
			t.Errorf("%s: want %q, got %q (err %v)", v.ID, v.Expect.Union, got, err)
		}
	}
}

func TestContainmentVectorsCorpus(t *testing.T) {
	var vectors []struct {
		ID     string `json:"id"`
		Parent Grant  `json:"parent"`
		Child  Grant  `json:"child"`
		Expect struct {
			Contains bool   `json:"contains"`
			Reason   string `json:"reason"`
		} `json:"expect"`
	}
	loadCorpus(t, "CLC_D_VECTORS", "clc-d/containment-vectors.json", &vectors)

	for _, v := range vectors {
		r := Contains(v.Parent, v.Child)
		ok := r.Contains == v.Expect.Contains &&
			(v.Expect.Contains || v.Expect.Reason == "" || canonicalCode(r.Reason) == canonicalCode(v.Expect.Reason))
		if !ok {
			t.Errorf("%s: contains want %v/%s, got %v/%s", v.ID, v.Expect.Contains,
				v.Expect.Reason, r.Contains, r.Reason)
		}
	}
}

func TestAuthorizeChainVectorsCorpus(t *testing.T) {
	var vectors []struct {
		ID      string     `json:"id"`
		Chain   []Grant    `json:"chain"`
		Request *Operation `json:"request"`
		Expect  struct {
			Verdict    string   `json:"verdict"`
			Reason     string   `json:"reason"`
			Unresolved []string `json:"unresolved"`
		} `json:"expect"`
	}
	loadCorpus(t, "CLC_AUTHORIZE_CHAIN_VECTORS", "clc-d/authorize-chain-vectors.json", &vectors)

	for _, v := range vectors {
		op := Operation{}
		if v.Request != nil {
			op = *v.Request
		}
		got := AuthorizeWithChain(v.Chain, op)
		if got.Verdict != v.Expect.Verdict || canonicalCode(got.Reason) != canonicalCode(v.Expect.Reason) {
			t.Errorf("%s: want %s/%s, got %s/%s", v.ID, v.Expect.Verdict,
				canonicalCode(v.Expect.Reason), got.Verdict, canonicalCode(got.Reason))
			continue
		}
		if v.Expect.Unresolved != nil && !slices.Equal(got.Unresolved, v.Expect.Unresolved) {
			t.Errorf("%s: unresolved want %v, got %v", v.ID, v.Expect.Unresolved, got.Unresolved)
		}
	}
}
