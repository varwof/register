// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command reason-collapse-vectors-run validates the CLC-D reason-code collapse
// policy vectors (capability-language-core-v1 §13.5) and then cross-checks them
// against the relation-level corpora: every code the policy declares
// non-collapsible MUST still be surfaced by the containment and cross-walk
// corpora, so "stays distinguishable" is observable by a third party, not just
// asserted in prose (CL 13.10.6).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Vector struct {
	ID            string  `json:"id"`
	Kind          string  `json:"kind"`
	SpecClause    string  `json:"spec_clause"`
	Code          string  `json:"code"`
	Collapsible   bool    `json:"collapsible"`
	CollapsibleTo *string `json:"collapsible_to"`
	Origin        string  `json:"origin"`
	Derivation    string  `json:"derivation"`
}

func load[T any](path string) ([]T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func codesFrom(path string) (map[string]bool, error) {
	type entry struct {
		Expect struct {
			Reason string `json:"reason"`
		} `json:"expect"`
	}
	entries, err := load[entry](path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Expect.Reason == "" {
			continue
		}
		seen[canonicalReason(e.Expect.Reason)] = true
	}
	return seen, nil
}

func canonicalReason(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

// codesFromExpect collects the distinct expect.pre_check values — the codes the
// profile-owned mode-lattice corpus exercises at its production layer.
func codesFromExpect(path string) (map[string]bool, error) {
	type entry struct {
		Expect struct {
			PreCheck string `json:"pre_check"`
		} `json:"expect"`
	}
	entries, err := load[entry](path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Expect.PreCheck != "" {
			seen[e.Expect.PreCheck] = true
		}
	}
	return seen, nil
}

func main() {
	here := filepath.Join("..", "capability", "data", "_vectors", "clc-d")
	rcPath := envOr("CLC_D_REASON_COLLAPSE_VECTORS", filepath.Join(here, "reason-collapse-vectors.json"))
	containPath := envOr("CLC_D_VECTORS", filepath.Join(here, "containment-vectors.json"))
	crossPath := envOr("CLC_D_CROSSWALK_VECTORS", filepath.Join(here, "containment-crosswalk-vectors.json"))

	vectors, err := load[Vector](rcPath)
	if err != nil {
		fatal("reason-collapse vectors", rcPath, err)
	}

	// 1. The policy itself must match §13.5: exactly the three registered
	//    codes, only child_exceeds_parent collapsible, and its only reduction
	//    is capability_not_authorized.
	policy := map[string]bool{}
	fail := 0
	for _, v := range vectors {
		policy[v.Code] = true
		ok := false
		switch v.Code {
		case "child_exceeds_parent":
			ok = v.Collapsible && v.CollapsibleTo != nil && *v.CollapsibleTo == "capability_not_authorized"
		case "params_not_narrower", "delegation_mode_not_narrower":
			ok = !v.Collapsible && v.CollapsibleTo == nil
		}
		if !ok {
			fail++
			fmt.Printf("POLICY FAIL %-6s %-28s collapsible=%v to=%v\n", v.ID, v.Code, v.Collapsible, deref(v.CollapsibleTo))
		} else {
			fmt.Printf("POLICY OK   %-6s %-28s collapsible=%v to=%v\n", v.ID, v.Code, v.Collapsible, deref(v.CollapsibleTo))
		}
	}
	for _, code := range []string{"child_exceeds_parent", "params_not_narrower", "delegation_mode_not_narrower"} {
		if !policy[code] {
			fmt.Printf("POLICY FAIL missing policy entry for %s\n", code)
			fail++
		}
	}
	if len(policy) != 3 {
		fmt.Printf("POLICY FAIL exactly three codes are registered, corpus declares %d\n", len(policy))
		fail++
	}

	// 2. Distinguishability cross-check (CL 13.10.6): a non-collapsible code
	//    must still be surfaced by the corpus of its own production layer, so a
	//    third party can observe that the implementation kept it
	//    distinguishable.  params_not_narrower comes from Contains (layers
	//    3-4): the containment and cross-walk corpora.  delegation_mode_not_narrower
	//    comes from the binding-profile pre-check (§13.4.5): the profile-owned
	//    mode-lattice corpus.
	containCodes, err := codesFrom(containPath)
	if err != nil {
		fatal("containment vectors", containPath, err)
	}
	crossCodes, err := codesFrom(crossPath)
	if err != nil {
		fatal("cross-walk vectors", crossPath, err)
	}
	modePath := envOr("CLC_D_MODE_VECTORS", filepath.Join(here, "profile-owned", "aic-jwt-da-mode-lattice-vectors.json"))
	modeCodes, err := codesFromExpect(modePath)
	if err != nil {
		fatal("mode-lattice vectors", modePath, err)
	}
	distinct := 0
	paramsSurfaced := containCodes["params_not_narrower"] || crossCodes["params_not_narrower"]
	for _, check := range []struct {
		code string
		ok   bool
	}{
		{"params_not_narrower", paramsSurfaced},
		{"delegation_mode_not_narrower", modeCodes["delegation_mode_not_narrower"]},
	} {
		if !check.ok {
			fail++
			fmt.Printf("DISTINCT FAIL %-28s is declared non-collapsible but no corpus of its production layer surfaces it\n", check.code)
		} else {
			distinct++
			fmt.Printf("DISTINCT OK   %-28s surfaced in its production layer\n", check.code)
		}
	}
	fmt.Printf("Total policy entries: %d | policy flags: %d | distinct codes surfaced: %d | failures: %d\n",
		len(vectors), countFlags(vectors), distinct, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if p := os.Getenv(key); p != "" {
		return p
	}
	return def
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func countFlags(vectors []Vector) int {
	n := 0
	for _, v := range vectors {
		if v.Collapsible {
			n++
		}
	}
	return n
}

func fatal(what, path string, err error) {
	fmt.Fprintf(os.Stderr, "Error reading %s from %s: %v\n", what, path, err)
	os.Exit(1)
}
