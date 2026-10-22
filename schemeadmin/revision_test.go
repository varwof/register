// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"fmt"
	"testing"
)

func TestRevisionComponentsDoNotOverflow(t *testing.T) {
	tooBig := "18446744073709551617"
	if _, err := MajorOf(tooBig + ".0"); err == nil {
		t.Fatalf("MajorOf(%q) accepted an overflowing component", tooBig)
	}
	if _, err := MinorOf("1." + tooBig); err == nil {
		t.Fatalf("MinorOf(%q) accepted an overflowing component", tooBig)
	}
	if n, err := MajorOf("42.7"); err != nil || n != 42 {
		t.Fatalf("MajorOf(42.7) = (%d, %v)", n, err)
	}
	if n, err := MinorOf("42.7"); err != nil || n != 7 {
		t.Fatalf("MinorOf(42.7) = (%d, %v)", n, err)
	}
}

func TestRevisionFollowsRefusesOverflow(t *testing.T) {
	max := fmt.Sprintf("%d", maxIntValue)
	if err := revisionFollows("1."+max, "1.0", ChangeMinor); err == nil {
		t.Fatal("minor advance at max int accepted")
	}
	if err := revisionFollows("0."+max, "1.0", ChangeMajor); err != nil {
		// major advance is independent of minor; this is a valid major bump.
		t.Fatalf("major advance with max minor rejected: %v", err)
	}
	if err := revisionFollows(max+".0", "0.0", ChangeMajor); err == nil {
		t.Fatal("major advance at max int accepted")
	}
	if err := revisionFollows("1.2", "1.3", ChangeMinor); err != nil {
		t.Fatalf("valid minor advance rejected: %v", err)
	}
}
