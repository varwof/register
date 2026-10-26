// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command verify-report verifies a signed CLC evidence report against a
// deployer policy, advances persisted snapshot state, and exits non-zero on any
// refusal.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register"
	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func parseRequirementDigest(raw string) (*semantics.Digest, error) {
	if raw == "" {
		return nil, nil
	}
	alg, value, ok := strings.Cut(raw, ":")
	if !ok || alg == "" || value == "" {
		return nil, fmt.Errorf("requirement digest must be <alg>:<base64url>")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("requirement digest value: %w", err)
	}
	return &semantics.Digest{Alg: alg, Value: decoded}, nil
}

func loadArtifacts(dir string) (map[projection.Digest][]byte, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	artifacts := make(map[projection.Digest][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) != 64 {
			continue
		}
		digest, err := projection.ParseDigest("sha-256:" + name)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		artifacts[digest] = raw
	}
	return artifacts, nil
}

func loadState(path string) (projection.SnapshotState, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return projection.ParseState(raw)
}

func main() {
	var verifiers stringList
	input := flag.String("in", "", "signed report JSON")
	ca := flag.String("CA", "", "report signer trust roots (file or directory)")
	tsa := flag.String("TSA", "", "timestamp authority roots (file or directory)")
	profileDigest := flag.String("profile", "", "pinned profile digest (sha-256:<hex>)")
	requirementDigest := flag.String("requirement", "", "pinned requirement digest (<alg>:<base64url>)")
	flag.Var(&verifiers, "verifier", "allowed verifier principal (repeatable)")
	minAssurance := flag.String("min-assurance", "", "minimum assurance: E1, E2 or E3")
	maxAge := flag.Duration("max-age", 0, "maximum report age")
	now := flag.String("now", "", "verification instant (RFC3339, default wall clock)")
	statePath := flag.String("state", "", "accepted snapshot state file")
	stateOut := flag.String("state-out", "", "write the next snapshot state here")
	artifactsDir := flag.String("artifacts", "", "directory of artifacts named <hex>")
	requireDerivations := flag.Bool("require-derivations", false, "require derivation records")
	requireArtifacts := flag.Bool("require-artifacts", false, "require artifact bytes for every derivation")
	requireTimestamp := flag.Bool("require-timestamp", false, "require a verified timestamp assertion")
	requireCheck := flag.String("require-check", "", "required check id (comma-separated, repeatable)")
	flag.Parse()

	if *input == "" || *ca == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-report -in <signed.json> -CA <roots> [flags]")
		fmt.Fprintln(os.Stderr, "note: E3 reports need a library caller that supplies an AttestationVerifier;")
		fmt.Fprintln(os.Stderr, "      the CLI verifies E1/E2 reports (it refuses an unverifiable attestation).")
		flag.PrintDefaults()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read signed report: %v\n", err)
		os.Exit(2)
	}
	signed, err := projection.DecodeSignedReport(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode signed report: %v\n", err)
		os.Exit(2)
	}

	policy := projection.ReportPolicy{
		RequireDerivations: *requireDerivations,
		RequireArtifacts:   *requireArtifacts,
		RequireTimestamp:   *requireTimestamp,
		MaxAge:             *maxAge,
	}
	if policy.Roots, err = register.LoadTrustRoots(*ca); err != nil {
		fmt.Fprintf(os.Stderr, "load trust roots: %v\n", err)
		os.Exit(2)
	}
	if *tsa != "" {
		if policy.TimestampRoots, err = register.LoadTrustRoots(*tsa); err != nil {
			fmt.Fprintf(os.Stderr, "load timestamp roots: %v\n", err)
			os.Exit(2)
		}
	}
	if *profileDigest != "" {
		if policy.ProfileDigest, err = projection.ParseDigest(*profileDigest); err != nil {
			fmt.Fprintf(os.Stderr, "profile digest: %v\n", err)
			os.Exit(2)
		}
	}
	if policy.RequirementDigest, err = parseRequirementDigest(*requirementDigest); err != nil {
		fmt.Fprintf(os.Stderr, "requirement digest: %v\n", err)
		os.Exit(2)
	}
	policy.VerifierPrincipals = verifiers
	if *minAssurance != "" {
		policy.MinAssurance = projection.AssuranceLevel(*minAssurance)
		if !policy.MinAssurance.Valid() {
			fmt.Fprintf(os.Stderr, "min-assurance %q is not E1|E2|E3\n", *minAssurance)
			os.Exit(2)
		}
	}
	if *now != "" {
		if policy.Now, err = time.Parse(time.RFC3339, *now); err != nil {
			fmt.Fprintf(os.Stderr, "now: %v\n", err)
			os.Exit(2)
		}
	}
	if policy.Snapshots, err = loadState(*statePath); err != nil {
		fmt.Fprintf(os.Stderr, "state: %v\n", err)
		os.Exit(2)
	}
	if *requireCheck != "" {
		for _, id := range strings.Split(*requireCheck, ",") {
			if id = strings.TrimSpace(id); id != "" {
				policy.RequiredCheckIDs = append(policy.RequiredCheckIDs, id)
			}
		}
	}
	if policy.Artifacts, err = loadArtifacts(*artifactsDir); err != nil {
		fmt.Fprintf(os.Stderr, "artifacts: %v\n", err)
		os.Exit(2)
	}

	report, next, err := projection.VerifySignedReport(signed, policy)
	if err != nil {
		code := projection.CodeOf(err)
		if code == "" {
			code = "internal"
		}
		fmt.Fprintf(os.Stderr, "REJECT %s: %v\n", code, err)
		os.Exit(1)
	}

	if *stateOut != "" {
		encoded, err := next.MarshalState()
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode state: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*stateOut, append(encoded, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write state: %v\n", err)
			os.Exit(1)
		}
	}
	bindings := next.Bindings()
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Source != bindings[j].Source {
			return bindings[i].Source < bindings[j].Source
		}
		return bindings[i].Generation < bindings[j].Generation
	})
	fmt.Printf("OK assurance=%s projector=%s snapshots=%d\n",
		report.Assurance, report.ProjectorID, len(bindings))
}
