// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackfillParamsSchemaDigests_Insert(t *testing.T) {
	in := []byte(`{
  "scheme_id": "x/test",
  "capabilities": [
    {
      "id": "a",
      "params_schema": {"type":"object"}
    },
    {
      "id": "b",
      "params_schema": {"type":"object","required":["x"]}
    }
  ]
}
`)

	out, err := BackfillParamsSchemaDigests(in)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}

	if bytes.Count(out, []byte(`"`+paramsSchemaDigestKey+`"`)) != 2 {
		t.Fatalf("expected 2 inserted digests, got %d:\n%s", bytes.Count(out, []byte(`"`+paramsSchemaDigestKey+`"`)), out)
	}

	// Output must still be valid JSON.
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}

	// Idempotent: running again must not change the bytes (and must not error).
	out2, err := BackfillParamsSchemaDigests(out)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("backfill not idempotent:\n%s\nvs\n%s", out, out2)
	}
}

func TestBackfillParamsSchemaDigests_BytesPreserved(t *testing.T) {
	in := []byte(`{"id":"a","params_schema":{"type":"object"},"summary":"keep me"}`)
	out, err := BackfillParamsSchemaDigests(in)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !strings.Contains(string(out), `"summary":"keep me"`) {
		t.Fatalf("sibling field not preserved: %s", out)
	}
	// params_schema value bytes must be untouched.
	if !strings.Contains(string(out), `"params_schema":{"type":"object"}`) {
		t.Fatalf("params_schema not preserved: %s", out)
	}
	// Digest must be a 64-char hex immediately as a sibling of params_schema.
	if !strings.Contains(string(out), `"params_schema":{"type":"object"}, "`+paramsSchemaDigestKey+`": "`) {
		t.Fatalf("digest not inserted adjacent to params_schema: %s", out)
	}
}

func TestBackfillParamsSchemaDigests_DriftDetected(t *testing.T) {
	in := []byte(`{"id":"a","params_schema":{"type":"object"},"summary":"x"}`)
	out, err := BackfillParamsSchemaDigests(in)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	// Corrupt the content but keep the stale stored digest → drift.
	stale := bytes.Replace(out, []byte(`{"type":"object"}`), []byte(`{"type":"array"}`), 1)
	if _, err := BackfillParamsSchemaDigests(stale); err == nil {
		t.Fatalf("expected drift error, got none")
	} else if !strings.Contains(err.Error(), "drift") {
		t.Fatalf("expected drift error mentioning drift, got: %v", err)
	}
}

func TestBackfillParamsSchemaDigests_NoParamsSchema(t *testing.T) {
	in := []byte(`{"id":"a","summary":"no schema"}`)
	out, err := BackfillParamsSchemaDigests(in)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("expected unchanged output, got %s", out)
	}
}

func TestBackfillParamsSchemaDigests_RealTestData(t *testing.T) {
	path := filepath.Join("testdata", "capability", "std", "database-v1", "v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}
	out, err := BackfillParamsSchemaDigests(data)
	if err != nil {
		t.Fatalf("backfill real file: %v", err)
	}
	if !bytes.Contains(data, []byte(`"`+paramsSchemaDigestKey+`"`)) {
		// data had no digest; output must have at least one and stay valid JSON.
		if !bytes.Contains(out, []byte(`"`+paramsSchemaDigestKey+`"`)) {
			t.Fatal("no digest inserted into real file")
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("real file output not valid JSON: %v", err)
	}
	// Idempotence on the real file.
	out2, err := BackfillParamsSchemaDigests(out)
	if err != nil {
		t.Fatalf("second backfill real file: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("real file backfill not idempotent")
	}
}
