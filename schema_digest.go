// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Byte-precise params_schema_digest backfill for capability data files.
//
// The capability JSON files under vendor/product/v*.json carry a JSON Schema
// in each capability's params_schema field. To detect drift (someone editing
// the schema out of band), gen-backfill inserts a params_schema_digest right
// after every params_schema, leaving every other byte untouched.
package register

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// paramsSchemaKey is the capability JSON key whose value is a JSON Schema.
const paramsSchemaKey = "params_schema"

// paramsSchemaDigestKey is the JSON object key inserted after params_schema.
const paramsSchemaDigestKey = "params_schema_digest"

// digestKeyLiteral is the JSON encoding of the digest key (including quotes).
const digestKeyLiteral = `"` + paramsSchemaDigestKey + `"`

// BackfillParamsSchemaDigests inserts a params_schema_digest field directly
// after each capability's params_schema field in a capability JSON document,
// preserving all other bytes exactly (key order, whitespace, omitempty
// zero-values).
//
// The digest is SHA-256 (hex-encoded) of the canonical (compacted) JSON of the
// params_schema value, so any semantic change to the schema is detected as
// drift while whitespace-only edits are not.
//
// A params_schema that already has a params_schema_digest declared immediately
// after it is verified for drift instead of modified: a stale digest returns an
// error. Documents without any params_schema are returned unchanged.
func BackfillParamsSchemaDigests(data []byte) ([]byte, error) {
	if !bytes.Contains(data, []byte(`"`+paramsSchemaKey+`"`)) {
		return data, nil
	}

	var out bytes.Buffer
	rest := data

	for {
		colon, err := findParamsSchemaKey(rest)
		if err != nil {
			return nil, err
		}
		if colon < 0 {
			out.Write(rest)
			break
		}

		// Copy everything up to the value start (key, ':', whitespace).
		valStart := skipJSONSpace(rest[colon+1:])
		if len(valStart) == 0 {
			return nil, errors.New("params_schema: unexpected end of input")
		}
		out.Write(rest[:colon+1+len(rest[colon+1:])-len(valStart)])

		// Parse the params_schema value (must be valid JSON).
		valEnd := valStart
		valEnd, err = skipJSONValue(valEnd)
		if err != nil {
			return nil, fmt.Errorf("params_schema value: %w", err)
		}
		valueBytes := valStart[:len(valStart)-len(valEnd)]
		out.Write(valueBytes)

		digest := sha256HexOf(valueBytes)

		// Inspect what follows the value.
		after := skipJSONSpace(valEnd)
		term := byte(0)
		if len(after) > 0 {
			term = after[0]
		}
		if term != ',' && term != '}' {
			return nil, errors.New("params_schema: unexpected character after value")
		}

		// If a comma precedes a digest key, the entry is already backfilled:
		// verify for drift and preserve the bytes unchanged.
		if term == ',' && bytes.HasPrefix(skipJSONSpace(after[1:]), []byte(digestKeyLiteral)) {
			// Raw span of the existing digest entry: from the comma after the
			// params_schema value through the end of the digest's string value.
			afterComma := after[1:]
			afterKey := skipJSONSpace(afterComma)
			if !bytes.HasPrefix(afterKey, []byte(digestKeyLiteral)) {
				return nil, errors.New("params_schema_digest: unexpected state")
			}
			afterColon := skipJSONSpace(afterKey[len(digestKeyLiteral):])
			if len(afterColon) == 0 || afterColon[0] != ':' {
				return nil, errors.New("params_schema_digest: expected ':'")
			}
			strVal := skipJSONSpace(afterColon[1:])
			strEnd := strVal
			strEnd, err = skipJSONValue(strEnd)
			if err != nil {
				return nil, fmt.Errorf("params_schema_digest value: %w", err)
			}
			rawEntryEnd := len(after) - len(strEnd)
			out.Write(after[:rawEntryEnd]) // copy comma + ws + key + ':' + ws + value verbatim

			var stored string
			storedBytes := strVal[:len(strVal)-len(strEnd)]
			if err := json.Unmarshal(storedBytes, &stored); err != nil {
				return nil, fmt.Errorf("params_schema_digest: %w", err)
			}
			if stored != digest {
				return nil, fmt.Errorf("params_schema_digest drift: stored %q != computed %q", stored, digest)
			}
			rest = strEnd
			continue
		}

		// Insert the digest as the next sibling key. The entry terminator is
		// ',' (more keys follow) or '}' (this is the last key).
		out.WriteByte(',')
		fmt.Fprintf(&out, " \"%s\": \"%s\"", paramsSchemaDigestKey, digest)
		if term == '}' {
			out.WriteByte('}')
			rest = skipJSONSpace(after[1:])
			continue
		}
		rest = after // unconsumed remainder includes the original comma + next key
	}

	return out.Bytes(), nil
}

// sha256HexOf returns the lowercase hex SHA-256 of the canonical (compacted)
// JSON form of raw. Compaction removes insignificant whitespace; key order is
// preserved, so reordering JSON object keys also changes the digest. On
// unparseable input the raw bytes are hashed as-is.
func sha256HexOf(raw []byte) string {
	compact := raw
	if c, err := compactJSON(raw); err == nil {
		compact = c
	}
	sum := sha256.Sum256(compact)
	return hex.EncodeToString(sum[:])
}

// compactJSON minimal-compacts a JSON value, dropping insignificant
// whitespace but otherwise leaving bytes intact (key order preserved).
func compactJSON(raw []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := json.Compact(buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// skipJSONValue returns the input with the leading JSON value removed. It
// handles objects, arrays, strings (with escapes), numbers, booleans, null.
func skipJSONValue(s []byte) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("unexpected end of input")
	}
	switch s[0] {
	case '{':
		return skipObject(s)
	case '[':
		return skipArray(s)
	case '"':
		return skipString(s)
	case 't':
		return skipLiteral(s, "true")
	case 'f':
		return skipLiteral(s, "false")
	case 'n':
		return skipLiteral(s, "null")
	default:
		return skipNumber(s)
	}
}

func skipObject(s []byte) ([]byte, error) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[i+1:], nil
			}
		case '"':
			rest, err := skipString(s[i:])
			if err != nil {
				return nil, err
			}
			i = len(s) - len(rest) - 1
		}
	}
	return nil, errors.New("unterminated object")
}

func skipArray(s []byte) ([]byte, error) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return s[i+1:], nil
			}
		case '"':
			rest, err := skipString(s[i:])
			if err != nil {
				return nil, err
			}
			i = len(s) - len(rest) - 1
		}
	}
	return nil, errors.New("unterminated array")
}

func skipString(s []byte) ([]byte, error) {
	if s[0] != '"' {
		return nil, errors.New("not a string")
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip escaped char
		case '"':
			return s[i+1:], nil
		}
	}
	return nil, errors.New("unterminated string")
}

func skipLiteral(s []byte, lit string) ([]byte, error) {
	if len(s) >= len(lit) && string(s[:len(lit)]) == lit {
		return s[len(lit):], nil
	}
	return nil, errors.New("invalid literal")
}

func skipNumber(s []byte) ([]byte, error) {
	i := 0
	for i < len(s) {
		c := s[i]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			i++
			continue
		}
		break
	}
	if i == 0 {
		return nil, errors.New("invalid number")
	}
	return s[i:], nil
}

// findParamsSchemaKey scans s for an object key "params_schema" (occurrences
// inside string values are ignored) and returns the index of the ':' that
// follows it, or -1 when not found.
func findParamsSchemaKey(s []byte) (int, error) {
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		rest, err := skipString(s[i:])
		if err != nil {
			return -1, err
		}
		keyEnd := len(s) - len(rest) // index just past the closing quote
		if string(s[i:keyEnd]) == `"`+paramsSchemaKey+`"` {
			after := skipJSONSpace(s[keyEnd:])
			if len(after) > 0 && after[0] == ':' {
				return len(s) - len(after), nil
			}
		}
		i = keyEnd - 1
	}
	return -1, nil
}

// skipJSONSpace trims insignificant JSON whitespace from the front of s.
func skipJSONSpace(s []byte) []byte {
	n := 0
	for n < len(s) {
		switch s[n] {
		case ' ', '\t', '\n', '\r':
			n++
		default:
			return s[n:]
		}
	}
	return s[n:]
}
