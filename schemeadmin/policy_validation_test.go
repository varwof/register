// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import "testing"

func TestValidatePolicyRejectsUnsafeValues(t *testing.T) {
	base := TrustPolicy{MaxMajor: 1}
	cases := []struct {
		name string
		mod  func(*TrustPolicy)
	}{
		{"negative approvals", func(p *TrustPolicy) { p.ApprovalThreshold = -1 }},
		{"negative staleness", func(p *TrustPolicy) { p.MaxStalenessSeconds = -1 }},
		{"threshold exceeds keys", func(p *TrustPolicy) { p.RootThreshold = 1 }},
		{"empty namespace prefix", func(p *TrustPolicy) { p.NamespacePrefixes = []string{""} }},
		{"relative namespace prefix", func(p *TrustPolicy) { p.NamespacePrefixes = []string{"std"} }},
		{"duplicate root key", func(p *TrustPolicy) {
			p.RootKeys = []string{
				"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			}
			p.RootThreshold = 1
		}},
		{"bad root key", func(p *TrustPolicy) { p.RootKeys = []string{"not-a-digest"}; p.RootThreshold = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mod(&p)
			if err := ValidatePolicy(p); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
