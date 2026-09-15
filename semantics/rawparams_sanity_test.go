package semantics

import (
	"fmt"
	"testing"
)

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
		{"lone_high_surrogate", `{"s":"\ud800"}`, ErrInvalidParamsNumber},
		{"lone_low_surrogate", `{"s":"\udc00"}`, ErrInvalidParamsNumber},
		{"surrogate_pair_ok", `{"s":"\ud83d\ude02"}`, nil},
		{"escaped_backslash_ok", `{"s":"\\ud800"}`, nil},
		{"lit_invalid_utf8_value", "{\"s\":\"\xff\"}", ErrInvalidParamsNumber},
		{"lit_invalid_utf8_key", "{\"\xff\":1}", ErrInvalidParamsNumber},
		{"lit_invalid_utf8_ws", "{\"s\":\"x\"\xff}", ErrInvalidParamsNumber},
		// Raw path measures octets in their JCS form (§3.2.2.2), so the size cap
		// matches the decoded path: `&` (raw, 1 octet), U+2028 (raw, 3), `"`/`\`
		// and the control shortcuts (two) and other controls (six) all hang on
		// the same boundary as Python/TS.  json.Marshal's HTML/U+2028 escaping
		// must not inflate the count.
		{"amp250", `{"s":"` + repeatAmp(250) + `"}`, nil},
		{"lt250", `{"s":"` + repeatLT(250) + `"}`, nil},
		{"u2028x160", `{"s":"` + repeatEsc(0x2028, 160) + `"}`, nil},
		{"u2028x169", `{"s":"` + repeatEsc(0x2028, 169) + `"}`, ErrInvalidParamsSize},
		{"quote250", `{"s":"` + repeatEsc(0x22, 250) + `"}`, nil},
		{"quote256", `{"s":"` + repeatEsc(0x22, 256) + `"}`, ErrInvalidParamsSize},
		{"backslash250", `{"s":"` + repeatEsc(0x5c, 250) + `"}`, nil},
		{"ctl_small_shortcut", `{"s":"` + repeatEsc(0x09, 250) + `"}`, nil},
		{"ctl_small250", `{"s":"` + repeatEsc(0x11, 250) + `"}`, ErrInvalidParamsSize},
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

// TestValidateObjectParamsUnicode pins the decoded-path Unicode boundary: a
// decoded params object that reaches the authorization APIs with invalid
// UTF-8 (or a lone surrogate carried as its raw three-byte form) must produce
// the same stable denial (invalid_params_number) the raw boundary returns,
// not a silent U+FFFD repair.  The JCS size check must measure the canonical
// bytes, so the 1e-6 case that deserializers measure as 512 JCS-counts as 515
// and is refused.
func TestValidateObjectParamsUnicode(t *testing.T) {
	calls := map[string]func(map[string]any) error{
		"grant": ValidateGrantParams,
		"op":    ValidateOperationParams,
	}
	invalid := map[string]map[string]any{
		"value invalid utf-8":   {"s": "\xff"},
		"key invalid utf-8":     {"\xff": 1},
		"lone surrogate 3-byte": {"s": "\xed\xa0\x80"},
	}
	for path, call := range calls {
		for name, params := range invalid {
			err := call(params)
			if !Is(err, ErrInvalidParamsNumber) {
				t.Errorf("%s/%s: got %v, want ErrInvalidParamsNumber", path, name, err)
			}
		}
	}
	// Valid UTF-8, including an astral pair, still passes; the null check is
	// unaffected.
	if err := ValidateOperationParams(map[string]any{"s": "名😀", "n": 1}); err != nil {
		t.Errorf("valid utf-8: got %v, want nil", err)
	}
	// json.dumps measures {"n":1e-06, "a":<494>} as 512 (allows); JCS
	// serializes 1e-6 as 0.000001 and measures 515 (refuse).
	over := map[string]any{"n": 1e-6, "a": repeat(494)}
	if err := ValidateOperationParams(over); !Is(err, ErrInvalidParamsSize) {
		t.Errorf("JCS-size 515 case: got %v, want ErrInvalidParamsSize", err)
	}
	if err := ValidateGrantParams(map[string]any{"n": 1e-6, "a": repeat(494)}); !Is(err, ErrInvalidParamsSize) {
		t.Errorf("JCS-size 515 case (grant): got %v, want ErrInvalidParamsSize", err)
	}
}

func TestRevisionCompatible(t *testing.T) {
	cases := []struct {
		rev  string
		want bool
	}{
		{"CLC-1.0", true},
		{"CLC-1.1", true},
		{"CLC-1.2", true},
		{"CLC-1.4", true},
		{"CLC-1.5", true},
		{"CLC-1.6", true},
		{"CLC-1.7", true},
		{"CLC-2.0", false},
		{"CLC-0.9", false},
		{"x-1.0", false},
		{"CLC-1", false},
		{"CLC-1.a", false},
		{"", false},
	}
	for _, c := range cases {
		if got := RevisionCompatible(c.rev); got != c.want {
			t.Errorf("RevisionCompatible(%q) = %v, want %v", c.rev, got, c.want)
		}
	}
	if CLCRevision != "CLC-1.7" {
		t.Errorf("CLCRevision = %q, want CLC-1.7", CLCRevision)
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

func repeatAmp(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += "&"
	}
	return s
}

func repeatLT(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += "<"
	}
	return s
}

// repeatEsc returns a JSON string value body consisting of n copies of the
// \uXXXX escape for cp.  cp must be a printable BMP code point representable
// as a four-digit escape (the caller wraps the result in {"s":"..."}).
func repeatEsc(cp, n int) string {
	esc := fmt.Sprintf("\\u%04x", cp)
	s := ""
	for i := 0; i < n; i++ {
		s += esc
	}
	return s
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
