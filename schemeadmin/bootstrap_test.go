// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/register/schemeadmin"
)

func TestBootstrapFixturePinsDeterministicKeys(t *testing.T) {
	path := filepath.Join("../../capability/data/_vectors/scheme-admin-v1/bootstrap.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("bootstrap fixture not found (capability checkout absent): %v", err)
	}
	var b struct {
		Policy struct {
			RootPackageDigest     string   `json:"root_package_digest"`
			RootKeys              []string `json:"root_keys"`
			NextRootPackageDigest string   `json:"next_root_package_digest"`
			NextRootKeys          []string `json:"next_root_keys"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	caCert, caKey := newCA(t, "bootstrap-ca")
	rootCert, _ := newPublisher(t, caCert, caKey, publisherSpec{Seed: "payments-admin", Principal: "principal:root-admin"})
	nextCert, _ := newPublisher(t, caCert, caKey, publisherSpec{Seed: "payments-admin-next", Principal: "principal:root-admin-next"})
	if len(b.Policy.RootKeys) != 1 || b.Policy.RootKeys[0] != schemeadmin.KeyID(rootCert) {
		t.Fatalf("bootstrap root_keys = %v, want [%s]", b.Policy.RootKeys, schemeadmin.KeyID(rootCert))
	}
	if len(b.Policy.NextRootKeys) != 1 || b.Policy.NextRootKeys[0] != schemeadmin.KeyID(nextCert) {
		t.Fatalf("bootstrap next_root_keys = %v, want [%s]", b.Policy.NextRootKeys, schemeadmin.KeyID(nextCert))
	}
	if b.Policy.RootPackageDigest == "" || strings.HasPrefix(b.Policy.RootPackageDigest, "sha256:AAAA") {
		t.Fatalf("bootstrap root_package_digest is not pinned")
	}
	if b.Policy.NextRootPackageDigest == "" || strings.HasPrefix(b.Policy.NextRootPackageDigest, "sha256:BBBB") {
		t.Fatalf("bootstrap next_root_package_digest is not pinned")
	}
}
