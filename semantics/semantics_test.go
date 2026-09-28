package semantics

import (
	"errors"
	"math"
	"testing"
)

func TestValidateCapabilityID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"std/database-v1:query:SELECT", true},
		{"std/database-v1:query:*", true},
		{"std/crm-v1:read", true},
		{"*", false},
		{"std/database-v1:query:SEL*", false},
		{"std/database-v1:query:{read,write}", false},
		{"std/database-v1:query:[a-z]", false},
		{"std/database-v1:**", false},
		{"", false},
		{"no-scheme", false},
	}
	for _, tt := range tests {
		err := ValidateCapabilityID(tt.id)
		if (err == nil) != tt.valid {
			t.Errorf("ValidateCapabilityID(%q) = %v, want valid=%v", tt.id, err, tt.valid)
		}
	}
}

func TestEntailment(t *testing.T) {
	tests := []struct {
		name    string
		grant   Grant
		op      Operation
		entails bool
	}{
		{"literal match", Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "std/database-v1:query:SELECT"}, true},
		{"wildcard match", Grant{ID: "std/database-v1:query:*"}, Operation{ID: "std/database-v1:query:SELECT"}, true},
		{"wildcard multi-segment", Grant{ID: "std/database-v1:query:*"}, Operation{ID: "std/database-v1:query:SELECT:deep"}, true},
		{"different namespace", Grant{ID: "std/database-v1:query:*"}, Operation{ID: "std/database-v1:admin:DDL"}, false},
		{"no trailing segment", Grant{ID: "std/database-v1:query:*"}, Operation{ID: "std/database-v1:query"}, false},
		{"literal mismatch", Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "std/database-v1:query:INSERT"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Entails(tt.grant, tt.op)
			if result.Entails != tt.entails {
				t.Errorf("Entails() = %v, want %v (reason: %s)", result.Entails, tt.entails, result.Reason)
			}
		})
	}
}

func TestParamsSubset(t *testing.T) {
	tests := []struct {
		name    string
		op      map[string]any
		grant   map[string]any
		entails bool
	}{
		{"number within bounds", map[string]any{"limit": float64(50)}, map[string]any{"limit": float64(100)}, true},
		{"number exceeds bounds", map[string]any{"limit": float64(150)}, map[string]any{"limit": float64(100)}, false},
		{"array subset", map[string]any{"tables": []any{"a"}}, map[string]any{"tables": []any{"a", "b"}}, true},
		{"array exceeds", map[string]any{"tables": []any{"a", "b"}}, map[string]any{"tables": []any{"a"}}, false},
		{"unconstrained grant", nil, nil, true},
		{"bounded grant, missing op", nil, map[string]any{"limit": float64(100)}, false},
		// R16 (audit 2026-09-16): key closure applies recursively inside
		// nested objects — an op key that the grant's nested object does not
		// declare is undeclared_param, exactly like the top level.
		{"nested equal", map[string]any{"cfg": map[string]any{"a": float64(1)}}, map[string]any{"cfg": map[string]any{"a": float64(1)}}, true},
		{"nested op keeps declared keys", map[string]any{"cfg": map[string]any{"a": float64(1), "b": float64(2)}}, map[string]any{"cfg": map[string]any{"a": float64(1), "b": float64(2)}}, true},
		{"nested op key undeclared", map[string]any{"cfg": map[string]any{"x": float64(1)}}, map[string]any{"cfg": map[string]any{"a": float64(1)}}, false},
		{"nested grant key missing in op", map[string]any{"cfg": map[string]any{"a": float64(1)}}, map[string]any{"cfg": map[string]any{"a": float64(1), "b": float64(2)}}, false},
		// A `{}` at the top level of the grant object is an explicit empty
		// bound (§9.3 layer 5): deny.  Only a *deeper* nested empty object
		// is unconstrained, matching the reference implementations.
		{"top-level empty object grant is empty bound", map[string]any{"cfg": map[string]any{"x": float64(1)}}, map[string]any{"cfg": map[string]any{}}, false},
		{"deep nested empty grant object is unconstrained", map[string]any{"cfg": map[string]any{"sub": map[string]any{"x": float64(1)}}}, map[string]any{"cfg": map[string]any{"sub": map[string]any{}}}, true},
		{"deep nested op key undeclared", map[string]any{"cfg": map[string]any{"sub": map[string]any{"x": float64(1)}}}, map[string]any{"cfg": map[string]any{"sub": map[string]any{"a": float64(1)}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Entails(Grant{ID: "std/database-v1:query:SELECT", Params: tt.grant}, Operation{ID: "std/database-v1:query:SELECT", Params: tt.op})
			if result.Entails != tt.entails {
				t.Errorf("Entails() = %v, want %v (reason: %s)", result.Entails, tt.entails, result.Reason)
			}
		})
	}
}

// TestValueSubsetNumericAndCrossType pins the CLC-1.15 numeric-representation
// audit (2026-09-25): the host numeric type is an encoding detail, so every Go
// integer/float is the same JSON number, while §6.5 layer 8 keeps JSON types
// distinct.  The old grant-side float64 branch plus the fmt.Sprintf("%v")
// fallback failed both ways — the string "50" satisfied the number 50
// (fail-open) and int/float equality was asymmetric.
func TestValueSubsetNumericAndCrossType(t *testing.T) {
	tests := []struct {
		name    string
		op      any
		grant   any
		entails bool
	}{
		// Numeric grant is an upper bound, whatever the host representation.
		{"float grant under", float64(50), float64(100), true},
		{"int grant under", 50, 100, true},
		{"int grant at bound", 100, 100, true},
		{"int grant over", 150, 100, false},
		{"int32 op under int64 grant", int32(50), int64(100), true},
		{"uint op under int grant", uint(50), 100, true},
		{"fractional op under int grant", 50.5, 100, true},
		// int and float are the same JSON number: symmetric in both directions.
		{"float op within int grant", float64(50), 100, true},
		{"int op within float grant", 50, float64(100), true},
		{"int op exceeds float grant", 150, float64(100), false},
		// §6.5 layer 8: JSON types stay distinct — a string never satisfies a
		// number, in either direction, for every host integer width.
		{"string op vs int grant", "50", 50, false},
		{"string op vs int64 grant", "50", int64(50), false},
		{"int op vs string grant", 50, "50", false},
		{"string op vs float grant", "50", float64(50), false},
		// A bool is not a number (§6.2).
		{"bool op vs int grant", true, 50, false},
		{"bool op vs float grant", true, float64(50), false},
		{"string op vs bool grant", "true", true, false},
		{"bool grant vs int op", true, 50, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": tt.grant}}
			op := Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": tt.op}}
			result := Entails(g, op)
			if result.Entails != tt.entails {
				t.Errorf("Entails() = %v, want %v (reason: %s)", result.Entails, tt.entails, result.Reason)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name    string
		grant   Grant
		op      Operation
		verdict string
	}{
		{"allow", Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "std/database-v1:query:SELECT"}, "allow"},
		{"deny no grant", Grant{}, Operation{ID: "std/database-v1:query:SELECT"}, "deny"},
		{"deny unknown constraint", Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{"unknown:constraint:type"}}, Operation{ID: "std/database-v1:query:SELECT"}, "deny"},
		{"deny invalid id", Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "invalid"}, "deny"},
		{"deny null params", Grant{ID: "std/database-v1:query:SELECT"}, Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": nil}}, "deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Authorize(tt.grant, tt.op)
			if result.Verdict != tt.verdict {
				t.Errorf("Authorize() = %v, want %v (reason: %s)", result.Verdict, tt.verdict, result.Reason)
			}
		})
	}
}

func TestNonFiniteParamsAreRejected(t *testing.T) {
	op := Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": math.NaN()}}
	if err := ValidateOperationParams(op.Params); !errors.Is(err, ErrInvalidParamsNumber) {
		t.Fatalf("NaN params: got %v, want ErrInvalidParamsNumber", err)
	}
	d := Authorize(Grant{ID: op.ID, Params: map[string]any{"limit": float64(100)}}, op)
	if d.Verdict != "deny" || d.Reason != "invalid_params_number" {
		t.Fatalf("NaN under a bound: got %+v, want deny/invalid_params_number", d)
	}
}

// TestIntersectCrossType pins the CLC-1.15 cross-type audit (2026-09-25):
// params intersection is JSON type-sensitive.  Strings, numbers and bools with
// the same printed form ("1" vs 1, "true" vs true, "1.5" vs 1.5) are distinct
// values (§6.5 layer 8); intersecting two grants that constrain one key to
// such values must deny no_overlap instead of merging into a wider grant.
// TestMaxRowsNativeIntegerOperands pins the CLC-1.15 max_rows operand audit
// (2026-09-25): the op-side row count is a number value, so a decoded JSON
// float64 and a programmatically-built native Go integer are the same value.
// The constraint evaluator must accept both, matching the Python/TS engines;
// the earlier float64-only type assertion denied native ints even though the
// params validator had already accepted them.
func TestMaxRowsNativeIntegerOperands(t *testing.T) {
	tests := []struct {
		name    string
		rows    any
		verdict string
	}{
		{"float64 under", float64(50), "allow"},
		{"int under", 50, "allow"},
		{"int equal bound", 100, "allow"},
		{"int32 under", int32(30), "allow"},
		{"int64 under", int64(30), "allow"},
		{"uint under", uint(30), "allow"},
		{"float64 over", float64(101), "deny"},
		{"int over", 101, "deny"},
		{"int64 over", int64(1000), "deny"},
		{"non-integer", 50.5, "deny"},
		{"negative", -1, "deny"},
		{"string", "50", "deny"},
		{"bool", true, "deny"},
		{"nil", nil, "deny"},
	}
	grant := Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{"varwof/constraint-v1:max_rows:100"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := Operation{ID: grant.ID, Params: map[string]any{"max_rows": tt.rows}}
			result := Authorize(grant, op)
			if result.Verdict != tt.verdict {
				t.Errorf("Authorize() = %v, want %v (reason: %s)", result.Verdict, tt.verdict, result.Reason)
			}
		})
	}
}

func TestIntersectCrossType(t *testing.T) {
	g := func(params map[string]any) Grant {
		return Grant{ID: "std/database-v1:query:SELECT", Params: params}
	}
	deny := []struct {
		name string
		a, b map[string]any
	}{
		{"string vs number", map[string]any{"x": "1"}, map[string]any{"x": float64(1)}},
		{"string vs bool", map[string]any{"x": "true"}, map[string]any{"x": true}},
		{"list string vs number", map[string]any{"x": []any{"1"}}, map[string]any{"x": []any{float64(1)}}},
		{"list bool vs string", map[string]any{"x": []any{true}}, map[string]any{"x": []any{"true"}}},
		{"list number vs string", map[string]any{"x": []any{float64(1.5)}}, map[string]any{"x": []any{"1.5"}}},
		{"nested scalar", map[string]any{"x": map[string]any{"a": "1"}}, map[string]any{"x": map[string]any{"a": float64(1)}}},
	}
	for _, tt := range deny {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Intersect(g(tt.a), g(tt.b)); !errors.Is(err, ErrNoOverlap) {
				t.Fatalf("Intersect(%q) = %v, want ErrNoOverlap", tt.name, err)
			}
		})
	}

	// Same-type numeric values are one value: [1] ∩ [1.0] = [1] (§2.4).
	m, err := Intersect(g(map[string]any{"x": []any{float64(1)}}),
		g(map[string]any{"x": []any{float64(1.0)}}))
	if err != nil {
		t.Fatalf("Intersect numeric same-value: %v", err)
	}
	if got := m.Params["x"]; len(got.([]any)) != 1 {
		t.Fatalf("Intersect numeric same-value = %v, want len 1", got)
	}
}
