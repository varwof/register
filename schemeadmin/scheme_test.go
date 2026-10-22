// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/register"
	"github.com/varwof/register/schemeadmin"
	"github.com/varwof/register/semantics"
)

// publishedSchemeFile resolves a file that the capability repository owns.  CI
// for this module does not check that repository out, so absence skips the
// artifact checks instead of failing them.
func publishedSchemeFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("../../capability/data/varwof/scheme-admin-v1", name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not found (capability checkout absent); skipping", p)
	}
	return p
}

// TestPublishedSchemeArtifacts checks that the scheme definition and its
// CLC-SCHEME-v1 declaration that this repository publishes are themselves
// valid under the repository's ordinary loaders.  A conformance corpus is
// worthless if the artifacts it describes do not load.
func TestPublishedSchemeArtifacts(t *testing.T) {
	defPath := publishedSchemeFile(t, "v1.json")
	declPath := publishedSchemeFile(t, "clc-declaration.json")

	def, err := register.LoadScheme(defPath)
	if err != nil {
		t.Fatalf("load scheme definition: %v", err)
	}
	if def.SchemeID != schemeadmin.SchemeID {
		t.Fatalf("scheme_id %q, want %q", def.SchemeID, schemeadmin.SchemeID)
	}
	errs, warns := def.ValidateSchemeRoles()
	for _, e := range errs {
		t.Errorf("role validation: %v", e)
	}
	for _, w := range warns {
		t.Logf("role warning: %s", w)
	}

	raw, err := os.ReadFile(declPath)
	if err != nil {
		t.Fatal(err)
	}
	decl, err := schemeadmin.ParseDeclaration(raw)
	if err != nil {
		t.Fatalf("parse declaration: %v", err)
	}
	if decl.Scheme != schemeadmin.SchemeID {
		t.Fatalf("declaration scheme %q, want %q", decl.Scheme, schemeadmin.SchemeID)
	}

	// Every administration capability must have a declared parameter domain,
	// otherwise namespace containment would silently degrade to equality.
	for _, capability := range []string{
		schemeadmin.CapCreate, schemeadmin.CapUpdate, schemeadmin.CapRevoke,
		schemeadmin.CapDelegate, schemeadmin.CapRootRotate, schemeadmin.CapApprove,
	} {
		dm := decl.DomainMap(capability)
		if len(dm) == 0 {
			t.Errorf("%s has no declared parameter domains", capability)
			continue
		}
		if dm["namespace"].Name != "" && dm["namespace"].Name != "path-prefix" {
			t.Errorf("%s namespace domain is %q, want path-prefix", capability, dm["namespace"].Name)
		}
	}
	if decl.DomainMap(schemeadmin.CapUpdate)["namespace"].Name != "path-prefix" {
		t.Fatal("scheme:update namespace must be declared path-prefix")
	}
}

// TestSchemeVerifyIsNotACapability pins the design's rule that verification is
// unprivileged: there is no scheme:verify capability to grant or delegate.
func TestSchemeVerifyIsNotACapability(t *testing.T) {
	raw, err := os.ReadFile(publishedSchemeFile(t, "clc-declaration.json"))
	if err != nil {
		t.Fatal(err)
	}
	decl, err := schemeadmin.ParseDeclaration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dm := decl.DomainMap("scheme:verify"); len(dm) != 0 {
		t.Fatalf("declaration declares scheme:verify with %d params", len(dm))
	}

	d := schemeadmin.Delegation{
		Grantee: "principal:observer",
		Parent: semantics.Grant{
			ID: schemeadmin.FullCapabilityID(schemeadmin.CapUpdate),
			Params: map[string]any{
				"namespace": "/std/payments-v1", "change_class": []string{"patch"},
				"major": 1, "clc_revision": []string{"CLC-1.19"},
			},
		},
		Child: semantics.Grant{
			ID: schemeadmin.FullCapabilityID("scheme:verify"),
			Params: map[string]any{
				"namespace": "/std/payments-v1", "change_class": []string{"patch"},
				"major": 1, "clc_revision": []string{"CLC-1.19"},
			},
		},
	}
	err = schemeadmin.ValidateDelegation(d, schemeadmin.TrustPolicy{})
	if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeDelegationNotContained {
		t.Fatalf("expected %q, got %q (%v)", schemeadmin.CodeDelegationNotContained, code, err)
	}
}
