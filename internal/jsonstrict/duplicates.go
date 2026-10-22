// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package jsonstrict provides the duplicate-member check that RFC 8785 (JCS)
// requires and encoding/json does not enforce.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type container struct {
	object    bool
	expectKey bool
	keys      map[string]bool
}

// Check rejects a JSON document with a duplicate object member at any depth.
// It is a full token scan; callers should apply a size bound first.
func Check(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []container
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		var top *container
		if len(stack) > 0 {
			top = &stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, container{object: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, container{object: false})
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("unexpected %q", t)
				}
				stack = stack[:len(stack)-1]
				if n := len(stack); n > 0 && stack[n-1].object {
					stack[n-1].expectKey = true
				}
			default:
				return fmt.Errorf("unexpected delimiter %q", t)
			}
		case string:
			if top != nil && top.object && top.expectKey {
				if top.keys[t] {
					return fmt.Errorf("duplicate object member %q", t)
				}
				top.keys[t] = true
				top.expectKey = false
			} else if top != nil && top.object {
				top.expectKey = true
			}
		default:
			if top != nil && top.object {
				top.expectKey = true
			}
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("unterminated JSON container")
	}
	return nil
}
