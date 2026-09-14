// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// RFC 8785 (JSON Canonicalization Scheme) canonical serialization.
//
// The CLC-v1 identifiers and digests are SHA-256 over the JCS encoding of a
// JSON value (the `clc-action:` projection and the Decision Record input
// digest).  Go's encoding/json is *not* JCS: it HTML-escapes `&`, `<` and `>`
// (so `{"value":"&"}` became `{"value":"\u0026"}`), it orders map keys by raw
// UTF-8 bytes rather than UTF-16 code units, and it does not normalize numbers
// to ECMAScript `Number::toString`.  Each of those changes the bytes and
// therefore the identifier, so two implementations that agreed on the JSON
// value disagreed on its digest.
//
// CanonicalJSON is the single entry point; it takes an arbitrary Go value
// (struct, map, slice, json.Number, …), rounds it through a decoded JSON tree
// so structs and maps take the same path, and emits the RFC 8785 form:
//
//   - object members are ordered by UTF-16 code units (§3.2.3);
//   - strings are escaped only as §3.2.2.2 requires: `"` and `\` get a
//     backslash, 0x08/0x09/0x0A/0x0C/0x0D use `\b`/`\t`/`\n`/`\f`/`\r`, the
//     remaining control characters use lowercase `\u00xx`, and every other
//     character (including `&`, `<`, `>` and non-ASCII) is emitted as raw
//     UTF-8;
//   - numbers follow ECMAScript `Number::toString` (§3.2.2.3): integers carry
//     no fraction or exponent, `-0` serializes as `0`;
//   - no insignificant whitespace; array order is preserved;
//   - invalid UTF-8 and lone surrogates are refused rather than silently
//     replaced with U+FFFD (which is what encoding/json would do).

package semantics

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrCanonicalInvalidUTF8 means a string (or object key) in the value is
	// not valid UTF-8.  JCS has no representation for it and silently
	// substituting U+FFFD would change the digest, so the encoding fails.
	ErrCanonicalInvalidUTF8 = errors.New("canonical_invalid_utf8")
	// ErrCanonicalSurrogate means a string contains a lone (unpaired) UTF-16
	// surrogate.  That is not encodable as UTF-8 either, and must not be
	// guessed at.
	ErrCanonicalSurrogate = errors.New("canonical_lone_surrogate")
	// ErrCanonicalNumber means a number is not representable as a finite
	// IEEE-754 double (the only numeric type JCS admits), e.g. `1e400`.
	ErrCanonicalNumber = errors.New("canonical_invalid_number")
)

// CanonicalJSON returns RFC 8785 (JCS) canonical JSON.
func CanonicalJSON(v any) ([]byte, error) {
	if err := validateCanonicalStrings(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	// Encode to an intermediate JSON text without HTML escaping.  This is the
	// only step that gives structs their JSON field names and ordering; the
	// bytes are then re-read as a tree so the JCS writer below is the single
	// authority on the final form.  The intermediate's own escaping (e.g.
	// \u2028 for U+2028) does not matter: the decoder turns it back into the
	// character and the JCS writer re-encodes it.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonicalJSON(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// validateCanonicalStrings walks v and refuses invalid UTF-8.  encoding/json
// would replace such bytes with U+FFFD; a canonical encoding must not, because
// that silently changes the digest.  Types that marshal themselves
// (json.Marshaler / encoding.TextMarshaler) are opaque here: their bytes never
// pass through this walk, so a malformed value from such a type is its own
// responsibility.
func validateCanonicalStrings(rv reflect.Value, depth int) error {
	if !rv.IsValid() {
		return nil
	}
	if depth > 1000 {
		return fmt.Errorf("%w: value nests deeper than 1000", ErrCanonicalInvalidUTF8)
	}
	for rv.Kind() == reflect.Interface || rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		switch rv.Kind() {
		case reflect.Interface:
			rv = rv.Elem()
		case reflect.Pointer:
			if rv.Type().Implements(jsonMarshalerType) || rv.Type().Implements(textMarshalerType) {
				return nil
			}
			rv = rv.Elem()
		}
	}
	if rv.CanInterface() {
		if _, ok := rv.Interface().(json.Marshaler); ok {
			return nil
		}
		if _, ok := rv.Interface().(encoding.TextMarshaler); ok {
			return nil
		}
	}
	switch rv.Kind() {
	case reflect.String:
		if err := checkCanonicalString(rv.String()); err != nil {
			return err
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			if k := iter.Key(); k.Kind() == reflect.String {
				if err := checkCanonicalString(k.String()); err != nil {
					return err
				}
			}
			if err := validateCanonicalStrings(iter.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8 {
			// encoding/json base64-encodes []byte; the bytes are not strings.
			return nil
		}
		for i := 0; i < rv.Len(); i++ {
			if err := validateCanonicalStrings(rv.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" { // unexported
				continue
			}
			if name, ok := field.Tag.Lookup("json"); ok {
				if strings.SplitN(name, ",", 2)[0] == "-" {
					continue
				}
			}
			if err := validateCanonicalStrings(rv.Field(i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// scanRawUnicodeEscapes refuses lone surrogate escapes in raw JSON text.
//
// The decoded path cannot enforce this: encoding/json substitutes U+FFFD for a
// lone surrogate escape before any checker sees the value, so the raw text is
// the only place the distinction still exists.  RFC 8785 requires such input to
// be refused, never repaired.
func scanRawUnicodeEscapes(raw string) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return nil // truncated escape: the decoder reports it
			}
			if raw[i+1] != 'u' {
				i++ // simple escape: step over the escaped character
				continue
			}
			hi, ok := hex4At(raw, i+2)
			if !ok {
				return nil // malformed escape: the decoder reports it
			}
			switch {
			case hi >= 0xDC00 && hi <= 0xDFFF:
				return fmt.Errorf("%w: lone low surrogate escape", ErrCanonicalSurrogate)
			case hi >= 0xD800 && hi <= 0xDBFF:
				if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
					return fmt.Errorf("%w: high surrogate escape without a low surrogate", ErrCanonicalSurrogate)
				}
				lo, ok := hex4At(raw, i+8)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return fmt.Errorf("%w: high surrogate escape not followed by a low surrogate", ErrCanonicalSurrogate)
				}
				i += 11 // consume the pair; the loop's i++ lands past it
			default:
				i += 5
			}
		}
	}
	return nil
}

// hex4At decodes four hex digits at off.
func hex4At(s string, off int) (int, bool) {
	if off+4 > len(s) {
		return 0, false
	}
	v := 0
	for _, c := range []byte(s[off : off+4]) {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// checkCanonicalString refuses invalid UTF-8 and lone surrogates.  A lone
// surrogate cannot be represented as a valid UTF-8 sequence (Go's string(rune)
// would itself substitute U+FFFD), so the two cases are distinguished by the
// three-byte form ED A0..BF 80..BF that an encoder would emit for one.
func checkCanonicalString(s string) error {
	if utf8.ValidString(s) {
		return nil
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF &&
				s[i+2] >= 0x80 && s[i+2] <= 0xBF {
				return fmt.Errorf("%w", ErrCanonicalSurrogate)
			}
			return fmt.Errorf("%w", ErrCanonicalInvalidUTF8)
		}
		i += size
	}
	return fmt.Errorf("%w", ErrCanonicalInvalidUTF8)
}

// writeCanonicalJSON serializes a decoded JSON tree in JCS form.
func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		s, err := canonicalNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case float64:
		s, err := canonicalNumber(strconv.FormatFloat(t, 'g', -1, 64))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unexpected JSON value of type %T", v)
	}
	return nil
}

// writeCanonicalString emits s per RFC 8785 §3.2.2.2.  The caller has already
// validated that s is UTF-8; bytes ≥ 0x80 are copied verbatim, so multi-byte
// sequences pass through unchanged.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			buf.WriteString(`\"`)
		case c == '\\':
			buf.WriteString(`\\`)
		case c == '\b':
			buf.WriteString(`\b`)
		case c == '\f':
			buf.WriteString(`\f`)
		case c == '\n':
			buf.WriteString(`\n`)
		case c == '\r':
			buf.WriteString(`\r`)
		case c == '\t':
			buf.WriteString(`\t`)
		case c < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hex[c>>4])
			buf.WriteByte(hex[c&0x0f])
		default:
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}

// canonicalNumber parses a JSON number literal and renders it with the
// ECMAScript Number::toString algorithm.  Every JSON number is an IEEE-754
// double for JCS purposes, so the literal is parsed to float64 first (a
// 20-digit integer is rounded exactly as ECMAScript would round it) and then
// re-rendered from the shortest round-tripping digits.
func canonicalNumber(lit string) (string, error) {
	if lit == "" {
		return "", fmt.Errorf("%w: empty number", ErrCanonicalNumber)
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrCanonicalNumber, lit)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %q", ErrCanonicalNumber, lit)
	}
	return formatCanonicalFloat(f), nil
}

// formatCanonicalFloat renders f the way ECMAScript's Number::toString does
// (RFC 8785 §3.2.2.3).  Let s be the shortest decimal digit string that
// round-trips to f and n the position of the decimal point (f = 0.s × 10^n).
// Then:
//
//	k ≤ n ≤ 21        digits followed by n−k zeros      (integers)
//	0 < n ≤ 21        first n digits '.' remaining      (fractions)
//	−6 < n ≤ 0        "0." (−n zeros) digits            (small fractions)
//	otherwise         exponential with a signed exponent
func formatCanonicalFloat(f float64) string {
	if f == 0 { // covers both +0 and -0
		return "0"
	}
	neg := math.Signbit(f)
	// 'e' format with -1 precision yields the shortest round-tripping digits
	// as "d[.ddd]e±XX".  The mantissa always has exactly one digit before the
	// point.
	mant := strconv.FormatFloat(math.Abs(f), 'e', -1, 64)
	expAt := strings.IndexByte(mant, 'e')
	exp10, _ := strconv.Atoi(mant[expAt+1:])
	digits := mant[:expAt]
	fracLen := 0
	if dot := strings.IndexByte(digits, '.'); dot >= 0 {
		fracLen = len(digits) - dot - 1
		digits = digits[:dot] + digits[dot+1:]
	}
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits)
	n := k + exp10 - fracLen

	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	switch {
	case k <= n && n <= 21:
		b.WriteString(digits)
		for i := 0; i < n-k; i++ {
			b.WriteByte('0')
		}
	case 0 < n && n <= 21:
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	case -6 < n && n <= 0:
		b.WriteString("0.")
		for i := 0; i < -n; i++ {
			b.WriteByte('0')
		}
		b.WriteString(digits)
	default:
		if k == 1 {
			b.WriteString(digits)
		} else {
			b.WriteByte(digits[0])
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		e := n - 1
		if e >= 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.Itoa(e))
	}
	return b.String()
}

// sortKeysUTF16 orders object keys by UTF-16 code units, the comparison RFC
// 8785 §3.2.3 requires.  UTF-16 order differs from UTF-8 byte order for
// astral code points: a surrogate pair (0xD800–0xDFFF) sorts below a BMP code
// point in the 0xE000–0xFFFF range, while its UTF-8 leading byte 0xF0 sorts
// above those code points' 0xEx leading bytes.
func sortKeysUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return utf16Less(keys[i], keys[j])
	})
}

func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
