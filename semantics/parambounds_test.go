package semantics

import (
	"encoding/json"
	"math/rand"
	"testing"
)

// TestParamBoundsEntailment pins the §6.5 Entails semantics that the vectors
// also exercise, at the unit level.
func TestParamBoundsEntailment(t *testing.T) {
	g := func(k string, b any) Grant {
		return Grant{ID: "std/database-v1:query:SELECT", ParamBounds: map[string]any{k: b}}
	}
	op := func(k string, v any) Operation {
		return Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{k: v}}
	}
	cases := []struct {
		name   string
		grant  Grant
		op     Operation
		wantOK bool
		reason string
	}{
		{"interval in range", g("limit", map[string]any{"min": 10.0, "max": 100.0}), op("limit", 50.0), true, ""},
		{"below min", g("limit", map[string]any{"min": 10.0}), op("limit", 5.0), false, "params_out_of_range"},
		{"step ok", g("n", map[string]any{"step": 0.5}), op("n", 1.5), true, ""},
		{"step bad", g("n", map[string]any{"step": 0.5}), op("n", 1.3), false, "params_not_multiple"},
		{"enum ok", g("t", map[string]any{"enum": []any{"a", "b"}}), op("t", []any{"a"}), true, ""},
		{"enum bad", g("t", map[string]any{"enum": []any{"a"}}), op("t", []any{"c"}), false, "not_in_enum"},
		{"cardinality bad", g("t", map[string]any{"max_items": 1.0}), op("t", []any{"a", "b"}), false, "params_cardinality"},
		{"required omitted", g("limit", map[string]any{"min": 0.0}), Operation{ID: "std/database-v1:query:SELECT"}, false, "params_missing"},
		{"optional omitted", g("limit", map[string]any{"min": 0.0, "optional": true}), Operation{ID: "std/database-v1:query:SELECT"}, true, ""},
		{"numeric on non-number", g("limit", map[string]any{"min": 0.0}), op("limit", "x"), false, "params_exceed_grant"},
	}
	for _, c := range cases {
		got := Entails(c.grant, c.op)
		if got.Entails != c.wantOK || canonicalPrefix(got.Reason) != c.reason {
			t.Errorf("%s: got entails=%v reason=%q, want entails=%v reason=%q",
				c.name, got.Entails, got.Reason, c.wantOK, c.reason)
		}
	}
}

func canonicalPrefix(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

// TestParamBoundsBindingRule pins the one-representation rule.
func TestParamBoundsBindingRule(t *testing.T) {
	grant := Grant{
		ID:          "std/database-v1:query:SELECT",
		Params:      map[string]any{"limit": 100.0},
		ParamBounds: map[string]any{"limit": map[string]any{"max": 50.0}},
	}
	op := Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 50.0}}
	got := Entails(grant, op)
	if got.Entails || canonicalPrefix(got.Reason) != "invalid_params_binding" {
		t.Fatalf("expected invalid_params_binding, got entails=%v reason=%q", got.Entails, got.Reason)
	}
}

// TestContainsParamBoundsNarrowing pins §13.4.3 narrowing for the new bounds.
func TestContainsParamBoundsNarrowing(t *testing.T) {
	pb := func(k string, b any) Grant {
		return Grant{ID: "std/database-v1:query:SELECT", ParamBounds: map[string]any{k: b}}
	}
	cases := []struct {
		name    string
		parent  Grant
		child   Grant
		contain bool
	}{
		{"interval nested", pb("limit", map[string]any{"min": 10.0, "max": 100.0}), pb("limit", map[string]any{"min": 20.0, "max": 80.0}), true},
		{"min lowered", pb("limit", map[string]any{"min": 10.0}), pb("limit", map[string]any{"min": 5.0}), false},
		{"max raised", pb("limit", map[string]any{"max": 100.0}), pb("limit", map[string]any{"max": 150.0}), false},
		{"enum subset", pb("t", map[string]any{"enum": []any{"a", "b"}}), pb("t", map[string]any{"enum": []any{"a"}}), true},
		{"enum adds", pb("t", map[string]any{"enum": []any{"a"}}), pb("t", map[string]any{"enum": []any{"a", "b"}}), false},
		{"step coarser", pb("n", map[string]any{"step": 0.25}), pb("n", map[string]any{"step": 0.5}), true},
		{"step finer", pb("n", map[string]any{"step": 0.5}), pb("n", map[string]any{"step": 0.25}), false},
		{"optional widened", pb("limit", map[string]any{"min": 0.0}), pb("limit", map[string]any{"min": 0.0, "optional": true}), false},
		{"optional tightened", pb("limit", map[string]any{"min": 0.0, "optional": true}), pb("limit", map[string]any{"min": 0.0}), true},
	}
	for _, c := range cases {
		got := Contains(c.parent, c.child)
		if got.Contains != c.contain {
			t.Errorf("%s: got contains=%v reason=%q, want %v", c.name, got.Contains, got.Reason, c.contain)
		}
	}
}

// TestIntersectBoundMeet pins the §6.6 BoundMeet (rev CLC-1.14): parametrized
// bounds now combine, per family, with empty/unrepresentable meets fail-closed.
func TestIntersectBoundMeet(t *testing.T) {
	const ID = "std/database-v1:query:SELECT"
	b := func(fields map[string]any) map[string]any { return map[string]any{"k": fields} }
	cases := []struct {
		name   string
		a, bb  map[string]any
		expect string // marshalled bound for key "k" on success
		err    error
	}{
		{"numeric max", b(map[string]any{"max": 100.0}), b(map[string]any{"max": 50.0}), `{"max":50}`, nil},
		{"numeric min/max", b(map[string]any{"min": 10.0, "max": 100.0}), b(map[string]any{"min": 20.0, "max": 80.0}), `{"max":80,"min":20}`, nil},
		{"step coarser", b(map[string]any{"step": 5.0}), b(map[string]any{"step": 10.0}), `{"step":10}`, nil},
		{"step incommensurable", b(map[string]any{"step": 5.0}), b(map[string]any{"step": 7.0}), "", ErrInvalidParamsBinding},
		{"numeric empty meet", b(map[string]any{"min": 10.0}), b(map[string]any{"max": 5.0}), "", ErrNoOverlap},
		{"enum intersect", b(map[string]any{"enum": []any{1.0, 2.0, 3.0}}), b(map[string]any{"enum": []any{2.0, 3.0, 4.0}}), `{"enum":[2,3]}`, nil},
		{"enum disjoint", b(map[string]any{"enum": []any{1.0}}), b(map[string]any{"enum": []any{2.0}}), "", ErrNoOverlap},
		{"numeric∩enum refused", b(map[string]any{"min": 2.0, "max": 4.0}), b(map[string]any{"enum": []any{1.0, 3.0, 5.0}}), "", ErrInvalidParamsBinding},
		{"enum∩numeric refused (order-independent)", b(map[string]any{"enum": []any{1.0, 3.0, 5.0}}), b(map[string]any{"min": 2.0, "max": 4.0}), "", ErrInvalidParamsBinding},
		{"numeric∩enum refused even when no member is in range", b(map[string]any{"min": 10.0, "max": 20.0}), b(map[string]any{"enum": []any{1.0, 3.0, 5.0}}), "", ErrInvalidParamsBinding},
		{"numeric∩cardinality-only", b(map[string]any{"max": 5.0}), b(map[string]any{"min_items": 1.0}), "", ErrInvalidParamsBinding},
		{"optional conjunction", b(map[string]any{"max": 5.0, "optional": true}), b(map[string]any{"max": 3.0}), `{"max":3}`, nil},
		{"optional both", b(map[string]any{"max": 5.0, "optional": true}), b(map[string]any{"max": 3.0, "optional": true}), `{"max":3,"optional":true}`, nil},
		{"nested recurse", b(map[string]any{"nested": map[string]any{"a": map[string]any{"max": 100.0}}}), b(map[string]any{"nested": map[string]any{"a": map[string]any{"max": 50.0}}}), `{"nested":{"a":{"max":50}}}`, nil},
		{"scalar∩nested refused", b(map[string]any{"max": 5.0}), b(map[string]any{"nested": map[string]any{"a": map[string]any{"max": 5.0}}}), "", ErrInvalidParamsBinding},
		{"nested∩scalar refused (order-independent)", b(map[string]any{"nested": map[string]any{"a": map[string]any{"max": 5.0}}}), b(map[string]any{"max": 5.0}), "", ErrInvalidParamsBinding},
		{"enum∩nested refused", b(map[string]any{"enum": []any{3.0}}), b(map[string]any{"nested": map[string]any{"a": map[string]any{"max": 5.0}}}), "", ErrInvalidParamsBinding},
		{"empty bound identity", b(map[string]any{}), b(map[string]any{"max": 7.0}), `{"max":7}`, nil},
	}
	for _, c := range cases {
		got, err := Intersect(
			Grant{ID: ID, ParamBounds: c.a},
			Grant{ID: ID, ParamBounds: c.bb},
		)
		if err != c.err {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.err)
			continue
		}
		if err != nil {
			continue
		}
		raw, _ := json.Marshal(got.ParamBounds["k"])
		if string(raw) != c.expect {
			t.Errorf("%s: bound = %s, want %s", c.name, raw, c.expect)
		}
	}
}

// TestBoundMeetProperties pins two laws of §6.6 over random bounds: the meet is
// commutative, and (when it succeeds) its result is within both sources.
func TestBoundMeetProperties(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	// Two bounds of the SAME family (plus the empty identity): boundWithin is
	// the §13.4.3 same-family narrowing check, so the law "meet is within both
	// sources" is stated over same-family pairs.  (A cross-family numeric ×
	// enum pair is refused outright since rev CLC-1.15, §6.6 — covered by the
	// table test above.)
	randBound := func(fam int) map[string]any {
		if r.Intn(4) == 0 {
			return map[string]any{}
		}
		switch fam {
		case 0:
			return map[string]any{"max": float64(1 + r.Intn(100))}
		case 1:
			return map[string]any{"min": float64(r.Intn(50)), "max": float64(50 + r.Intn(50))}
		case 2:
			return map[string]any{"enum": []any{float64(1 + r.Intn(3)), float64(1 + r.Intn(3))}}
		default:
			return map[string]any{"nested": map[string]any{"a": map[string]any{"max": float64(1 + r.Intn(10))}}}
		}
	}
	for i := 0; i < 20000; i++ {
		fam := r.Intn(4)
		a, b := randBound(fam), randBound(fam)
		m1, e1 := boundMeet(a, b)
		m2, e2 := boundMeet(b, a)
		if (e1 == nil) != (e2 == nil) || (e1 != nil && e1 != e2) {
			t.Fatalf("commutativity of errors: %v vs %v on %v/%v", e1, e2, a, b)
		}
		if e1 != nil {
			continue
		}
		raw1, _ := json.Marshal(m1)
		raw2, _ := json.Marshal(m2)
		if string(raw1) != string(raw2) {
			t.Fatalf("commutativity: %s vs %s on %v/%v", raw1, raw2, a, b)
		}
		if err := boundWithin(m1, a); err != nil {
			t.Fatalf("meet %s not within A %v: %v", raw1, a, err)
		}
		if err := boundWithin(m1, b); err != nil {
			t.Fatalf("meet %s not within B %v: %v", raw1, b, err)
		}
	}
}

// TestIntersectBoundCrossSite pins §6.6 "Key site": one source declaring a key
// in params and another in param_bounds is refused.
func TestIntersectBoundCrossSite(t *testing.T) {
	const ID = "std/database-v1:query:SELECT"
	_, err := Intersect(
		Grant{ID: ID, Params: map[string]any{"k": 100.0}},
		Grant{ID: ID, ParamBounds: map[string]any{"k": map[string]any{"max": 50.0}}},
	)
	if err != ErrInvalidParamsBinding {
		t.Fatalf("cross-site err = %v, want %v", err, ErrInvalidParamsBinding)
	}
}

// TestAuthorizeWithChainParamBounds pins that a delegation chain whose hops use
// param_bounds is authorizable and that the ancestor bound stays in force.
func TestAuthorizeWithChainParamBounds(t *testing.T) {
	const ID = "std/database-v1:query:SELECT"
	chain := []Grant{
		{ID: ID, ParamBounds: map[string]any{"limit": map[string]any{"max": 100.0}}},
		{ID: ID, ParamBounds: map[string]any{"limit": map[string]any{"max": 50.0}}},
	}
	if d := AuthorizeWithChain(chain, Operation{ID: ID, Params: map[string]any{"limit": 10.0}}); d.Verdict != VerdictAllow {
		t.Fatalf("limit=10: %s/%s, want allow", d.Verdict, d.Reason)
	}
	if d := AuthorizeWithChain(chain, Operation{ID: ID, Params: map[string]any{"limit": 75.0}}); d.Verdict != VerdictDeny || d.Reason != ErrParamsOutOfRange.Error() {
		t.Fatalf("limit=75: %s/%s, want deny/%s", d.Verdict, d.Reason, ErrParamsOutOfRange)
	}
}
