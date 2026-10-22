// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import "testing"

func TestDecodeClosedRejectsTrailingData(t *testing.T) {
	accept := []string{"", " ", "\n\t", "\r\n"}
	for _, suffix := range accept {
		var v struct{}
		if err := decodeClosed([]byte(`{}`+suffix), &v); err != nil {
			t.Errorf("suffix %q: unexpected error: %v", suffix, err)
		}
	}

	reject := []string{"garbage", "\x00", "]", "}", "{}", "null", " 1", ",", " /*x*/"}
	for _, suffix := range reject {
		var v struct{}
		if err := decodeClosed([]byte(`{}`+suffix), &v); err == nil {
			t.Errorf("suffix %q: accepted trailing data", suffix)
		}
	}
}
