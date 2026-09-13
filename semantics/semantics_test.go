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
