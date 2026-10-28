// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command report-vectors-run evaluates the internal report-layer regression
// vectors.
//
// These vectors cover the internal report layer only (validation,
// completeness, lifecycle and replay). They are data-only: no private keys and
// no signatures, so signed-report behaviour stays in the projection unit tests.
// The corpus is internal regression evidence, not a conformance suite.
//
// Corpus path: EVIDENCE_REPORT_VECTORS, else the first argument.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/varwof/register/projection"
)

type vectorPolicy struct {
	RequireProfile         bool                         `json:"requireProfile"`
	RequireComplete        bool                         `json:"requireComplete"`
	AllowIncomplete        bool                         `json:"allowIncomplete"`
	RequireSnapshotBinding bool                         `json:"requireSnapshotBinding"`
	RequireReplay          bool                         `json:"requireReplay"`
	MinAssurance           string                       `json:"minAssurance"`
	RequiredCheckIDs       []string                     `json:"requiredCheckIds"`
	SnapshotSources        []string                     `json:"snapshotSources"`
	Snapshots              []projection.SnapshotBinding `json:"snapshots"`
	ReplayArtifacts        []struct {
		Digest projection.Digest `json:"digest"`
		Bytes  string            `json:"bytes"`
	} `json:"replayArtifacts"`
}

type vector struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Report json.RawMessage `json:"report"`
	Policy vectorPolicy    `json:"policy"`
	Want   struct {
		Verdict string `json:"verdict"`
		Code    string `json:"code"`
	} `json:"want"`
}

type corpus struct {
	Version string   `json:"@version"`
	Cases   []vector `json:"cases"`
}

func (v vector) policy() projection.ReportPolicy {
	policy := projection.ReportPolicy{
		RequireProfile:         v.Policy.RequireProfile,
		RequireComplete:        v.Policy.RequireComplete,
		AllowIncomplete:        v.Policy.AllowIncomplete,
		RequireSnapshotBinding: v.Policy.RequireSnapshotBinding,
		RequireReplay:          v.Policy.RequireReplay,
		MinAssurance:           projection.AssuranceLevel(v.Policy.MinAssurance),
		RequiredCheckIDs:       v.Policy.RequiredCheckIDs,
		SnapshotSources:        v.Policy.SnapshotSources,
		Snapshots:              projection.NewSnapshotState(v.Policy.Snapshots...),
	}
	if len(v.Policy.ReplayArtifacts) > 0 {
		policy.ReplayEvidence = make(map[projection.Digest][]byte, len(v.Policy.ReplayArtifacts))
		for _, artifact := range v.Policy.ReplayArtifacts {
			policy.ReplayEvidence[artifact.Digest] = []byte(artifact.Bytes)
		}
	}
	return policy
}

// evaluate runs one vector and returns the observed verdict and stable code.
func evaluate(v vector) (string, string, error) {
	dec := json.NewDecoder(bytes.NewReader(v.Report))
	dec.DisallowUnknownFields()
	var report projection.Report
	if err := dec.Decode(&report); err != nil {
		return "reject", "report_shape", fmt.Errorf("decode report: %w", err)
	}

	var err error
	switch v.Kind {
	case "validate":
		err = projection.ValidateEvidenceReport(&report)
	case "verify":
		err = projection.VerifyEvidenceReport(&report, v.policy())
	case "lifecycle":
		_, err = projection.CheckReportLifecycle(&report, v.policy())
	default:
		return "reject", "internal", fmt.Errorf("unknown vector kind %q", v.Kind)
	}
	if err == nil {
		return "accept", "", nil
	}
	var reportErr *projection.ReportError
	if errors.As(err, &reportErr) {
		return "reject", reportErr.Code, err
	}
	return "reject", "internal", err
}

func main() {
	path := os.Getenv("EVIDENCE_REPORT_VECTORS")
	if path == "" && len(os.Args) > 1 {
		path = os.Args[1]
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: report-vectors-run <vectors.json> (or EVIDENCE_REPORT_VECTORS)")
		os.Exit(2)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read corpus: %v\n", err)
		os.Exit(2)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintf(os.Stderr, "parse corpus: %v\n", err)
		os.Exit(2)
	}

	verbose := os.Getenv("CLC_E_VERBOSE") != ""
	failures := 0
	for _, v := range c.Cases {
		verdict, code, err := evaluate(v)
		if err != nil && code == "internal" {
			verdict, code = "error", "internal"
			fmt.Fprintf(os.Stderr, "%s: %v\n", v.ID, err)
		} else if err != nil && verbose {
			fmt.Fprintf(os.Stderr, "%s: %v\n", v.ID, err)
		}
		want := v.Want.Verdict
		if v.Want.Code != "" {
			want += "/" + v.Want.Code
		}
		got := verdict
		if code != "" {
			got += "/" + code
		}
		status := "PASS"
		if got != want {
			status = "FAIL"
			failures++
		}
		fmt.Printf("%s %s %-56s want=%s got=%s\n", status, v.ID, v.Name, want, got)
	}
	if failures != 0 {
		fmt.Fprintf(os.Stderr, "%d case(s) failed\n", failures)
		os.Exit(1)
	}
}
