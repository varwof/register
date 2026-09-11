package semantics

import "testing"

func TestValidateRawParams(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"ok_basic", `{"limit": 100, "tag": "x"}`, nil},
		{"ok_compact", `{"columns":{"t":["id","name"]}}`, nil},
		{"dup_key", `{"limit":100,"limit":150}`, ErrInvalidParamsDupKey},
		{"dup_nested", `{"a":{"b":1,"b":2}}`, ErrInvalidParamsDupKey},
		{"nonfinite", `{"limit":1e400}`, ErrInvalidParamsNumber},
		{"bigint", `{"limit":12345678901234567890}`, ErrInvalidParamsNumber},
		{"precision", `{"x":0.1234567890123456789}`, ErrInvalidParamsNumber},
		{"size600", `{"s":"` + repeat(600) + `"}`, ErrInvalidParamsSize},
		{"size_depth33", `{"d":` + repeatNest(32) + `0` + repeatClose(32) + `}`, ErrInvalidParamsSize},
		{"depth32_ok", `{"d":` + repeatNest(31) + `0` + repeatClose(31) + `}`, nil},
		{"malformed", `{"limit": 100,`, ErrInvalidParamsNumber},
		{"notobject", `[1,2]`, ErrInvalidParamsNumber},
		{"empty", ``, ErrInvalidParamsNumber},
		{"nan_junk", `{"x": tru}`, ErrInvalidParamsNumber},
	}
	for _, c := range cases {
		err := ValidateRawParams(c.raw)
		if c.wantErr == nil {
			if err != nil {
				t.Errorf("%s: got %v, want nil", c.name, err)
			}
			continue
		}
		if !Is(err, c.wantErr) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.wantErr)
		}
	}
}

func TestRevisionCompatible(t *testing.T) {
	cases := []struct {
		rev  string
		want bool
	}{
		{"CLC-1.0", true},
		{"CLC-1.1", true},
		{"CLC-1.2", true}, // impl declares 1.1; 1.2 > 1.1 → false below
		{"CLC-2.0", false},
		{"CLC-0.9", false},
		{"x-1.0", false},
		{"CLC-1", false},
		{"CLC-1.a", false},
		{"", false},
	}
	// fix: 1.2 should be false (minor > ours)
	for i := range cases {
		if cases[i].rev == "CLC-1.2" {
			cases[i].want = false
		}
	}
	for _, c := range cases {
		if got := RevisionCompatible(c.rev); got != c.want {
			t.Errorf("RevisionCompatible(%q) = %v, want %v", c.rev, got, c.want)
		}
	}
	if CLCRevision != "CLC-1.1" {
		t.Errorf("CLCRevision = %q, want CLC-1.1", CLCRevision)
	}
}

// Is is a small errors.Is wrapper for the test file.
func Is(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func repeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func repeatNest(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += `{"x":`
	}
	return s
}

func repeatClose(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += `}`
	}
	return s
}
