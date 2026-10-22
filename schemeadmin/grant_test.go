// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"testing"

	pki "github.com/varwof/types"

	"github.com/varwof/register/semantics"
)

func TestGrantsForWildcardAndParamBounds(t *testing.T) {
	aic := &pki.AIC{Capabilities: []pki.Capability{{
		SchemeId:     SchemeID,
		CapabilityId: "scheme:*",
		Parameters:   []byte(`{"param_bounds":{"major":{"max":3}}}`),
	}}}
	full := FullCapabilityID("scheme:create")
	grants := grantsFor(aic, full)
	if len(grants) != 1 {
		t.Fatalf("grants = %+v", grants)
	}
	if grants[0].ID != SchemeID+":scheme:*" {
		t.Fatalf("wildcard grant id lost: %q", grants[0].ID)
	}
	if len(grants[0].ParamBounds) == 0 || len(grants[0].Params) != 0 {
		t.Fatalf("param_bounds envelope misdecoded: %+v", grants[0])
	}
	if res := semantics.Entails(grants[0], semantics.Operation{ID: full, Params: map[string]any{"major": float64(2)}}); !res.Entails {
		t.Fatalf("major 2 not entailed: %+v", res)
	}
	if res := semantics.Entails(grants[0], semantics.Operation{ID: full, Params: map[string]any{"major": float64(4)}}); res.Entails {
		t.Fatalf("major 4 entailed under max 3: %+v", res)
	}
}

func TestGrantsForBareParams(t *testing.T) {
	aic := &pki.AIC{Capabilities: []pki.Capability{{
		SchemeId:     SchemeID,
		CapabilityId: "scheme:create",
		Parameters:   []byte(`{"namespace":"/std"}`),
	}}}
	grants := grantsFor(aic, FullCapabilityID("scheme:create"))
	if len(grants) != 1 || grants[0].Params["namespace"] != "/std" {
		t.Fatalf("bare params misdecoded: %+v", grants)
	}
}
