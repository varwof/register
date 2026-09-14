// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalJSONReferenceSuite replays the RFC 8785 reference vectors from
// the cyberphone/json-canonicalization project (testdata/canonicalization,
// Apache-2.0).  Each `<name>.in.json` is a non-canonical document and
// `<name>.out.json` is its JCS encoding; the input is parsed with UseNumber so
// number literals reach the canonicalizer unrounded, exactly as the reference
// harness does.
func TestCanonicalJSONReferenceSuite(t *testing.T) {
	names := []string{"arrays", "french", "structures", "unicode", "values", "weird"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", "jcs", name+".in.json"))
			if err != nil {
				t.Fatalf("read input: %v", err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "jcs", name+".out.json"))
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			dec := json.NewDecoder(bytes.NewReader(in))
			dec.UseNumber()
			var tree any
			if err := dec.Decode(&tree); err != nil {
				t.Fatalf("parse input: %v", err)
			}
			got, err := CanonicalJSON(tree)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if string(got) != strings.TrimRight(string(want), "\n") {
				t.Fatalf("canonical mismatch\n got  = %s\n want = %s", got, strings.TrimRight(string(want), "\n"))
			}
		})
	}
}
