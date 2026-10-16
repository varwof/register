// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ModeVector is one binding-profile delegation-mode pre-check case
// (core §13.4.5).  Delegation mode is a carrier concept: Grant values carry no
// mode and Contains takes no mode argument, so a mode-carrying carrier's
// binding profile runs the lattice check itself and reports
// delegation_mode_not_narrower FROM THE PROFILE.  The language corpus does not
// carry these vectors; a carrier that binds a mode owns its own lattice — that
// aggregation point is capped by SpecClause, never by the CLC-D class.
type ModeVector struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	SpecClause string  `json:"spec_clause"`
	Profile    string  `json:"profile"`
	ParentMode *string `json:"parent_mode"`
	ChildMode  *string `json:"child_mode"`
	Expect     struct {
		PreCheck string `json:"pre_check"`
	} `json:"expect"`
	Derivation string `json:"derivation"`
}

// DefaultModePath is where the AIC-JWT DA mode-lattice corpus lives relative to
// the register module.
const DefaultModePath = "../capability/data/_vectors/clc-d/profile-owned/aic-jwt-da-mode-lattice-vectors.json"

// ModePath returns the mode-lattice corpus location, honouring
// CLC_D_MODE_VECTORS.
func ModePath() string {
	if p := os.Getenv("CLC_D_MODE_VECTORS"); p != "" {
		return p
	}
	return filepath.FromSlash(DefaultModePath)
}

// LoadMode reads an AIC-JWT DA mode-lattice corpus file.
func LoadMode(path string) ([]ModeVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vectors []ModeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, err
	}
	return vectors, nil
}

// RunMode evaluates every mode-lattice vector.
func RunMode(vectors []ModeVector) []Result {
	out := make([]Result, 0, len(vectors))
	for _, v := range vectors {
		out = append(out, runModeVector(v))
	}
	return out
}

func runModeVector(v ModeVector) Result {
	r := Result{ID: v.ID, Kind: v.Kind, Expect: v.Expect.PreCheck}
	got, err := ModePreCheck(v.Profile, v.ParentMode, v.ChildMode)
	if err != nil {
		r.Got, r.Note = "error", err.Error()
		return r
	}
	r.Got = got
	r.Pass = got == v.Expect.PreCheck
	if v.ParentMode != nil && v.ChildMode != nil {
		r.Note = fmt.Sprintf("parent=%s child=%s", *v.ParentMode, *v.ChildMode)
	}
	return r
}

// ModePreCheck runs the binding-profile delegation-mode pre-check for a named
// carrier profile and returns "narrows" or "delegation_mode_not_narrower".
// The lattice order is carrier-defined: the AIC-JWT order is
// authorized < representative.  A carrier with no mode concept (both nil) has
// no lattice to consult and the check passes.
func ModePreCheck(profile string, parentMode, childMode *string) (string, error) {
	switch profile {
	case "aic-jwt-da->clc-v1":
		return aicJWTModesNarrow(parentMode, childMode)
	default:
		return "", fmt.Errorf("unknown mode-lattice profile %q", profile)
	}
}

// aicJWTModesNarrow applies the AIC-JWT order authorized < representative
// (core §13.4.5): a child may be authorized under a representative parent,
// never the reverse.
func aicJWTModesNarrow(parentMode, childMode *string) (string, error) {
	rank := func(m *string) (int, error) {
		if m == nil {
			return -1, nil // no mode bound
		}
		switch *m {
		case "authorized":
			return 0, nil
		case "representative":
			return 1, nil
		default:
			return 0, fmt.Errorf("unknown AIC-JWT delegation mode %q", *m)
		}
	}
	pr, err := rank(parentMode)
	if err != nil {
		return "", err
	}
	cr, err := rank(childMode)
	if err != nil {
		return "", err
	}
	if pr < 0 || cr < 0 {
		// No mode on either side: nothing binds a lattice.
		return "narrows", nil
	}
	if cr <= pr {
		return "narrows", nil
	}
	return "delegation_mode_not_narrower", nil
}
