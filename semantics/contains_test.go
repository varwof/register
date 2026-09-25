package semantics

import (
	"testing"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		parent Grant
		child  Grant
		want   bool
		reason string
	}{
		// Layer 2: identifier coverage (§4.1)
		{"literal equal", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/database-v1:query:SELECT"}, true, ""},
		{"child narrower id", Grant{ID: "std/database-v1:query:*"}, Grant{ID: "std/database-v1:query:SELECT"}, true, ""},
		{"child wildcard broader than literal parent", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/database-v1:query:*"}, false, "child_exceeds_parent"},
		{"child outside parent path", Grant{ID: "std/database-v1:query:*"}, Grant{ID: "std/database-v1:admin:DDL"}, false, "different_namespace"},
		{"different namespace", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/crm-v1:read"}, false, "different_namespace"},

		// Layer 3: parameter narrowing (§4.2)
		{"parent unconstrained contains bounded child", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(50)}}, true, ""},
		{"number upper bound tighter", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(50)}}, true, ""},
		{"number upper bound equal", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, true, ""},
		{"child bound exceeds parent", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(150)}}, false, "params_not_narrower"},
		{"enum subset", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"tables": []any{"a", "b", "c"}}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"tables": []any{"a", "b"}}}, true, ""},
		{"enum element outside parent", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"tables": []any{"a", "b"}}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"tables": []any{"a", "z"}}}, false, "params_not_narrower"},
		{"child omits parent key", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100), "offset": float64(10)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(50)}}, false, "params_not_narrower"},
		{"child adds parent-undeclared key", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(50), "extra": float64(1)}}, false, "params_not_narrower"},
		{"child unconstrained under bounded parent", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT"}, false, "params_not_narrower"},
		{"nested object tighter", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"cfg": map[string]any{"limit": float64(100)}}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"cfg": map[string]any{"limit": float64(50)}}}, true, ""},
		{"nested object wider", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"cfg": map[string]any{"limit": float64(50)}}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"cfg": map[string]any{"limit": float64(100)}}}, false, "params_not_narrower"},

		// Constraints are NOT part of the relation: they compose by union
		// across a delegation chain (§7 Intersect), never by subset here.
		// They are exercised in TestContainsIgnoresConstraints.

		// Combined
		{"fully narrower params", Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(100)}}, Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(50)}}, true, ""},
		{"id mismatch dominates", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/database-v1:admin:DDL"}, false, "different_namespace"},

		// Layer 1: validity
		{"invalid parent id", Grant{ID: "std/database-v1:query:SEL*"}, Grant{ID: "std/database-v1:query:SELECT"}, false, "unsupported_wildcard"},
		{"invalid child id", Grant{ID: "std/database-v1:query:SELECT"}, Grant{ID: "std/database-v1:**"}, false, "unsupported_wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Contains(tt.parent, tt.child)
			if got.Contains != tt.want {
				t.Errorf("Contains() = %v, want %v (reason: %s)", got.Contains, tt.want, got.Reason)
			}
			if tt.reason != "" && got.Reason != tt.reason {
				t.Errorf("Contains() reason = %q, want %q", got.Reason, tt.reason)
			}
		})
	}
}

// TestContainsIgnoresConstraints pins the deliberate design decision that
// constraints are NOT part of the containment relation.  Constraints compose by
// union across a delegation chain (Intersect, §7), not by subset; Contains
// compares identifier and parameters only, so a constraint difference never
// changes its verdict.
func TestContainsIgnoresConstraints(t *testing.T) {
	G := "std/database-v1:query:SELECT"
	tests := []struct {
		name    string
		parentC []string
		childC  []string
	}{
		{"child constraint tighter", []string{"varwof/constraint-v1:max_rows:100"}, []string{"varwof/constraint-v1:max_rows:50"}},
		{"child constraint wider", []string{"varwof/constraint-v1:max_rows:50"}, []string{"varwof/constraint-v1:max_rows:100"}},
		{"child adds constraint parent lacks", nil, []string{"varwof/constraint-v1:max_rows:50"}},
		{"child drops parent constraint", []string{"varwof/constraint-v1:max_rows:50"}, nil},
		{"unknown constraint identity", []string{`foo/db-v1:max_rows:100`}, []string{`foo/db-v1:max_rows:10`}},
		{"invalid constraint value", []string{"varwof/constraint-v1:max_rows:100"}, []string{"varwof/constraint-v1:max_rows:notanint"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := Grant{ID: G, Constraints: tt.parentC}
			child := Grant{ID: G, Constraints: tt.childC}
			if got := Contains(parent, child); !got.Contains {
				t.Errorf("Contains() = false (%s), want true: constraints must not affect containment", got.Reason)
			}
		})
	}
}
