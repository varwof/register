// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/varwof/register/projection"
)

// The internal test schema is documentation-only at runtime (no JSON-Schema
// dependency is pulled in), so this test keeps it honest: every JSON member of
// the report-layer types must appear in the schema, and the schema's required
// sets must match the fields the validator actually enforces.
func TestReportSchemaCoversReportLayerTypes(t *testing.T) {
	raw, err := os.ReadFile("testdata/evidence-report-v1.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
		Defs       map[string]struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	cases := []struct {
		name     string
		def      string
		value    any
		required []string
	}{
		{"Report", "", projection.Report{}, []string{"@version", "assurance", "projectorId", "nativeChecksComplete"}},
		{"NativeCheckResult", "nativeCheckResult", projection.NativeCheckResult{}, []string{
			"checkId", "componentType", "evidenceDigest", "outcome",
			"verifier", "verifierProfileDigest", "verificationTime",
		}},
		{"NativeCheckExpectation", "expectation", projection.NativeCheckExpectation{}, []string{
			"checkId", "componentType", "evidenceDigest",
		}},
		{"NativeCheckAssessment", "nativeCheckAssessment", projection.NativeCheckAssessment{}, []string{"complete"}},
		{"NativeCheckConflict", "conflict", projection.NativeCheckConflict{}, []string{
			"checkId", "componentType", "outcomes",
		}},
		{"ProjectedObservation", "observation", projection.ProjectedObservation{}, nil},
		{"ProjectedEvidenceRecord", "evidenceRecord", projection.ProjectedEvidenceRecord{}, []string{"artifactDigest"}},
		{"FreshnessDecision", "freshnessDecision", projection.FreshnessDecision{}, []string{"verdict"}},
		{"Profile", "profile", projection.Profile{}, []string{"id", "statusModel"}},
		{"Derivation", "derivation", projection.Derivation{}, []string{
			"carrierId", "artifactDigest", "verifierProfileDigest", "factIndex", "factDigest",
		}},
		{"Attestation", "attestation", projection.Attestation{}, []string{"type", "digest", "quote"}},
		{"TimestampAssertion", "timestampAssertion", projection.TimestampAssertion{}, []string{
			"digest", "time", "token",
		}},
		{"SignedReport", "signedReport", projection.SignedReport{}, []string{"envelope"}},
		{"ReplayEvidence", "replayEvidence", projection.ReplayEvidence{}, []string{
			"@version", "checkId", "componentType", "evidenceDigest", "outcome",
			"verifier", "verifierProfileDigest",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			props := schema.Properties
			required := schema.Required
			if tc.def != "" {
				def, ok := schema.Defs[tc.def]
				if !ok {
					t.Fatalf("schema has no $defs/%s", tc.def)
				}
				props = def.Properties
				required = def.Required
			}
			for _, name := range jsonMemberNames(tc.value) {
				if _, ok := props[name]; !ok {
					t.Errorf("%s member %q is missing from the schema", tc.name, name)
				}
			}
			if got, want := sortedStrings(required), sortedStrings(tc.required); !reflect.DeepEqual(got, want) {
				t.Errorf("%s schema required = %v, validator enforces %v", tc.name, got, want)
			}
		})
	}
}

// jsonMemberNames returns the JSON names of a struct's exported fields.
func jsonMemberNames(v any) []string {
	typ := reflect.TypeOf(v)
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
