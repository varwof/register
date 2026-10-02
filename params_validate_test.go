// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"strings"
	"testing"
)

func vsp(t *testing.T, capability, params string) error {
	t.Helper()
	return ValidateSchemeParams("std/database-v1", capability, []byte(params))
}

func vspOK(t *testing.T, capability, params string) {
	t.Helper()
	if err := vsp(t, capability, params); err != nil {
		t.Fatalf("%s %s must be accepted: %v", capability, params, err)
	}
}

func vspErr(t *testing.T, capability, params, want string) {
	t.Helper()
	err := vsp(t, capability, params)
	if err == nil {
		t.Fatalf("%s %s must be rejected, got nil", capability, params)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s %s: error %q does not contain %q", capability, params, err, want)
	}
}

// TestSelectParams_PredicateAllowlist pins the decided semantics: a declared
// filter_columns list binds first (even over "*"), then the returnable column
// set, and a "*" or unlisted columns entry means unrestricted.
func TestSelectParams_PredicateAllowlist(t *testing.T) {
	// filter_columns declared -> only its members may appear in WHERE.
	vspErr(t, "query:SELECT", `{"tables":["t"],"columns":{"t":["a","b"]},
			"filter_columns":{"t":["tenant"]},
			"row_filter":{"t":{"column":"a","op":"=","value":1}}}`, "outside the column allowlist")
	vspOK(t, "query:SELECT", `{"tables":["t"],"columns":{"t":["a","b"]},
			"filter_columns":{"t":["tenant"]},
			"row_filter":{"t":{"column":"tenant","op":"=","value":"x"}}}`)
	// filter_columns bind even when the returnable list is "*".
	vspErr(t, "query:SELECT", `{"tables":["t"],"columns":{"t":"*"},
			"filter_columns":{"t":["tenant"]},
			"row_filter":{"t":{"column":"a","op":"=","value":1}}}`, "outside the column allowlist")
	// no filter_columns -> the returnable set is the predicate allowlist.
	vspOK(t, "query:SELECT", `{"tables":["t"],"columns":{"t":["a","b"]},
			"row_filter":{"t":{"column":"a","op":"=","value":1}}}`)
	vspErr(t, "query:SELECT", `{"tables":["t"],"columns":{"t":["a","b"]},
			"row_filter":{"t":{"column":"other","op":"=","value":1}}}`, "outside the column allowlist")
	// a table named in tables but absent from columns is unrestricted (isStar).
	vspOK(t, "query:SELECT", `{"tables":["t"],"columns":{},
			"row_filter":{"t":{"column":"anything","op":"=","value":1}}}`)
	vspOK(t, "query:SELECT", `{"tables":["t"],"columns":{"t":"*"},
			"row_filter":{"t":{"column":"anything","op":"=","value":1}}}`)
}

// TestSelectParams_OrderByIsNotDeclared pins that order_by belongs to the
// writes only; carrying it on SELECT is a contract error, not a silent no-op.
func TestSelectParams_OrderByIsNotDeclared(t *testing.T) {
	vspErr(t, "query:SELECT", `{"tables":["t"],"columns":{"t":["a"]},"order_by":["a"]}`,
		"only declared by query:UPDATE and query:DELETE")
}

// TestUpdateParams pins the write-side contract: row_filter required,
// filter_columns/limit/order_by declared, and structural rules enforced.
func TestUpdateParams(t *testing.T) {
	// base is the full JSON minus its final closing brace, so callers append
	// either `}` or `,"key":...}`.
	base := `{"tables":["orders"],"columns":{"orders":["status"]},
			"row_filter":{"orders":{"column":"status","op":"=","value":"paid"}}`
	vspOK(t, "query:UPDATE", base+`}`)
	// a row cap with a grant-side deterministic order is the whole point.
	vspOK(t, "query:UPDATE", base+`,"limit":{"max":10},"order_by":["id"]}`)
	// the predicate allowlist is shared with SELECT.
	vspOK(t, "query:UPDATE", `{"tables":["orders"],"columns":{"orders":["status"]},
			"filter_columns":{"orders":["tenant"]},
			"row_filter":{"orders":{"column":"tenant","op":"=","value":"org-a"}}}`)
	vspErr(t, "query:UPDATE", `{"tables":["orders"],"columns":{"orders":["status"]},
			"row_filter":{"orders":{"column":"tenant","op":"=","value":"org-a"}}}`, "outside the column allowlist")
	// row_filter is the reason UPDATE exists: it can never be omitted.
	vspErr(t, "query:UPDATE", `{"tables":["orders"],"columns":{"orders":["status"]}}`,
		"row_filter is required")
	vspErr(t, "query:UPDATE", base+`,"limit":{"max":0}}`, "limit.max must be in 1..100000")
	vspErr(t, "query:UPDATE", base+`,"limit":{"max":100001}}`, "limit.max must be in 1..100000")
	vspErr(t, "query:UPDATE", base+`,"order_by":[]}`, "must name at least one column")
	vspErr(t, "query:UPDATE", base+`,"order_by":["id","id"]}`, "must be unique")
	vspErr(t, "query:UPDATE", base+`,"order_by":[""]}`, "non-empty column names")
}

// TestDeleteParams pins the DELETE-side contract: row_filter required, no
// columns needed, and the same limit/order_by rules as UPDATE.
func TestDeleteParams(t *testing.T) {
	base := `{"tables":["logs"],"row_filter":{"logs":{"column":"tenant","op":"=","value":"org-a"}}`
	vspOK(t, "query:DELETE", base+`}`)
	vspOK(t, "query:DELETE", base+`,"limit":{"max":500},"order_by":["ts"]}`)
	vspOK(t, "query:DELETE", `{"tables":["logs"],"columns":{"logs":["ts"]},
			"row_filter":{"logs":{"column":"ts","op":"<","value":1700000000}}}`)
	vspErr(t, "query:DELETE", `{"tables":["logs"]}`, "row_filter is required")
	vspErr(t, "query:DELETE", base+`,"order_by":["ts","ts"]}`, "must be unique")
}
