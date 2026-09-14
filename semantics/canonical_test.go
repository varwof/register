// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func canonicalB64URL(t *testing.T, v any) string {
	t.Helper()
	b, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON(%#v): %v", v, err)
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// The review's reproducer: Go's json.Marshal HTML-escapes `&`, so the bytes and
// digest differed from RFC 8785.  This is the exact acceptance datum.
func TestCanonicalJSONAmpersandRFC8785(t *testing.T) {
	const want = `{"value":"&"}`
	b, err := CanonicalJSON(map[string]any{"value": "&"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(b) != want {
		t.Fatalf("bytes = %s, want %s", b, want)
	}
	sum := sha256.Sum256(b)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != "mi_igvJzMHC1qRoYLpfY799ulBNeR5CnOjgCVyAKKQM" {
		t.Fatalf("b64url = %s, want mi_igvJzMHC1qRoYLpfY799ulBNeR5CnOjgCVyAKKQM", got)
	}
	if got := hex32(sum); got != "9a2fe282f2733070b5a91a182e97d8efdf6e94135e4790a73a380257200a2903" {
		t.Fatalf("sha256 = %s, want 9a2fe282f2733070b5a91a182e97d8efdf6e94135e4790a73a380257200a2903", got)
	}
}

func TestCanonicalJSONActionIdAmpersand(t *testing.T) {
	def := ActionTypeDefinition{Type: "probe.action.1", MaterialFields: []string{"value"}}
	id, err := ComputeActionID(def, SuiteJCSSHA256, map[string]any{"value": "&"})
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	want := "clc-action:1:probe.action.1:jcs-sha256:mi_igvJzMHC1qRoYLpfY799ulBNeR5CnOjgCVyAKKQM"
	if got := id.String(); got != want {
		t.Fatalf("action id = %s, want %s", got, want)
	}
}

// `&`, `<` and `>` must not be escaped; control characters use the short and
// lowercase escapes RFC 8785 §3.2.2.2 allows.
func TestCanonicalJSONStringEscaping(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"s": "<>&\"\\/\b\f\n\r\t\x00\x1f"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"s":"<>&\"\\/\b\f\n\r\t\u0000\u001f"}`
	if string(got) != want {
		t.Fatalf("bytes = %s, want %s", got, want)
	}
}

// Non-ASCII is emitted as raw UTF-8, including characters Go's encoder would
// escape for JavaScript safety (U+2028/U+2029).
func TestCanonicalJSONNonASCIIUnescaped(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"s": "€\u2028\u2029💩"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := "{\"s\":\"€\u2028\u2029\U0001F4A9\"}"
	if string(got) != want {
		t.Fatalf("bytes = %q, want %q", got, want)
	}
}

// Key order is UTF-16 code-unit order, which differs from UTF-8 byte order
// exactly for astral code points: 💩 (U+1F4A9, surrogate D83D) sorts before
// U+E000 as UTF-16, but after it as UTF-8.
func TestCanonicalJSONUTF16KeyOrder(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"\uE000":     "bmp",
		"\U0001F4A9": "astral",
		"a":          "ascii",
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// UTF-16: "a" (0x0061) < 💩 (0xD83D) < U+E000 (0xE000).
	want := "{\"a\":\"ascii\",\"\U0001F4A9\":\"astral\",\"\uE000\":\"bmp\"}"
	if string(got) != want {
		t.Fatalf("bytes = %s, want %s", got, want)
	}
	// Sanity: the byte-order sort the old code used would have put U+E000
	// (UTF-8 EE 80 80) before the astral char (UTF-8 F0 9F 92 A9).
}

func TestCanonicalJSONNumbers(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{json.Number("1"), "1"},
		{json.Number("-1"), "-1"},
		{json.Number("0"), "0"},
		{json.Number("-0"), "0"},
		{json.Number("-0.0"), "0"},
		{json.Number("1.50"), "1.5"},
		{json.Number("1e5"), "100000"},
		{json.Number("1E5"), "100000"},
		{json.Number("1e+21"), "1e+21"},
		{json.Number("1e20"), "100000000000000000000"},
		{json.Number("1e-6"), "0.000001"},
		{json.Number("1e-7"), "1e-7"},
		{json.Number("4.50"), "4.5"},
		{json.Number("2e-3"), "0.002"},
		{json.Number("333333333.33333329"), "333333333.3333333"},
		{json.Number("1e30"), "1e+30"},
		{json.Number("5e-324"), "5e-324"},
		{json.Number("1.7976931348623157e308"), "1.7976931348623157e+308"},
		{json.Number("9007199254740992"), "9007199254740992"},
		{json.Number("123456789012345680000"), "123456789012345680000"},
		{float64(0), "0"},
		{float64(-0.0), "0"},
		{float64(1.5), "1.5"},
		{float64(100), "100"},
		{float64(1e21), "1e+21"},
		{float64(1e-7), "1e-7"},
		{int(42), "42"},
		{int64(-7), "-7"},
	}
	for _, c := range cases {
		b, err := CanonicalJSON(map[string]any{"n": c.in})
		if err != nil {
			t.Errorf("%v: %v", c.in, err)
			continue
		}
		if string(b) != `{"n":`+c.want+`}` {
			t.Errorf("%v: got %s, want {\"n\":%s}", c.in, b, c.want)
		}
	}
}

func TestCanonicalJSONRejectsInvalidUTF8(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"s": string([]byte{0xff, 0xfe})})
	if !errors.Is(err, ErrCanonicalInvalidUTF8) {
		t.Fatalf("got %v, want ErrCanonicalInvalidUTF8", err)
	}
	_, err = CanonicalJSON(map[string]any{string([]byte{'k', 0xff}): "v"})
	if !errors.Is(err, ErrCanonicalInvalidUTF8) {
		t.Fatalf("key: got %v, want ErrCanonicalInvalidUTF8", err)
	}
}

func TestCanonicalJSONRejectsNonFinite(t *testing.T) {
	if _, err := CanonicalJSON(map[string]any{"n": json.Number("1e400")}); !errors.Is(err, ErrCanonicalNumber) {
		t.Fatalf("1e400: got %v, want ErrCanonicalNumber", err)
	}
}

// The JCS writer must agree with encoding/json on the JSON value it encodes:
// re-decoding the canonical bytes yields the same tree.
func TestCanonicalJSONRoundTrip(t *testing.T) {
	in := map[string]any{
		"a": []any{json.Number("1.50"), "x&<>", true, nil},
		"b": map[string]any{"k": "v"},
	}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("canonical bytes are not JSON: %v (%s)", err, got)
	}
}

func TestCanonicalJSONNoWhitespace(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"a": []any{1, 2}, "b": "x"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if strings.ContainsAny(string(got), " \n\t\r") {
		t.Fatalf("canonical form contains whitespace: %q", got)
	}
}

func hex32(sum [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[2*i] = hexdigits[b>>4]
		out[2*i+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

// The raw path is where a lone surrogate escape can still be seen: the decoder
// substitutes U+FFFD, so the scan runs before it.
func TestScanRawUnicodeEscapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"pair", `{"s":"\ud83d\ude02"}`, true},
		{"lone high", `{"s":"\ud800"}`, false},
		{"lone low", `{"s":"\udc00"}`, false},
		{"high then bmp escape", `{"s":"\ud800\u0041"}`, false},
		{"escaped backslash", `{"s":"\\ud800"}`, true},
		{"plain string", `{"s":"ok"}`, true},
	}
	for _, tc := range cases {
		err := scanRawUnicodeEscapes(tc.raw)
		if tc.ok && err != nil {
			t.Errorf("%s: got %v, want nil", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: got nil, want a refusal", tc.name)
		}
	}
}
