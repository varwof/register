// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package jsonstrict

import "testing"

func TestCheckRejectsDuplicateMembers(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":2}}`,
		`{"a":[{"b":1,"b":2}]}`,
		`{"a":1,"b":{"c":2,"c":3},"d":4}`,
	}
	for _, raw := range bad {
		if err := Check([]byte(raw)); err == nil {
			t.Errorf("accepted duplicate keys: %s", raw)
		}
	}
}

func TestCheckAcceptsUniqueMembers(t *testing.T) {
	good := []string{
		`{}`,
		`{"a":1,"b":2}`,
		`{"a":{"b":1,"c":2},"d":[{"e":1},{"f":2}]}`,
		`[1,2,{"a":1,"b":2}]`,
		`"scalar"`,
	}
	for _, raw := range good {
		if err := Check([]byte(raw)); err != nil {
			t.Errorf("rejected valid JSON %s: %v", raw, err)
		}
	}
}
