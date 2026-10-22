// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"strings"
	"testing"
)

// TestParseDecimalCanonicalOnly pins the §6.7 `decimal-string` grammar: only a
// canonical decimal literal (optionally with an exponent) is accepted.  The
// fraction, hexadecimal and digit-separator forms big.Rat.SetString also parses
// are not decimals and must be refused (audit finding N-12).
func TestParseDecimalCanonicalOnly(t *testing.T) {
	accept := []string{
		"500", "500.00", "1e3", "1000", "499.99", "+500", "-500",
		"0", "-0", "007", "1E3", "1e+3", "1e-3",
		"1e10000", "1e-10000", "1e+10000",
	}
	for _, s := range accept {
		if _, ok := parseDecimal(s); !ok {
			t.Errorf("parseDecimal(%q) = reject, want accept", s)
		}
	}

	reject := []string{
		"3/2", "1/3", "0x10", "0X10", "1_000", // big.Rat.SetString over-accepts these
		"500.", ".5", "inf", "Infinity", "nan", "NaN", "sNaN",
		" 500 ", "500 ", " 500",
		"1e", "e3", ".", "", "1.2.3", "--5", "1..2", "+",
		// Exponent overflow and the bounded allocation rule.
		"1e10001", "1e-10001", "1e9223372036854775808", "1e-9223372036854775808",
		"1e100000000",
	}
	for _, s := range reject {
		if _, ok := parseDecimal(s); ok {
			t.Errorf("parseDecimal(%q) = accept, want reject", s)
		}
	}
}

func TestParseDecimalRejectsOversizedMantissa(t *testing.T) {
	s := strings.Repeat("1", maxDecimalMantissa+1)
	if _, ok := parseDecimal(s); ok {
		t.Fatal("oversized mantissa accepted")
	}
	// A mantissa at the bound remains valid.
	s = strings.Repeat("1", maxDecimalMantissa)
	if _, ok := parseDecimal(s); !ok {
		t.Fatal("mantissa at the bound rejected")
	}
}

// TestDecimalContainmentRejectsExponentOverflow is the regression for the
// authority bypass: before the bound, 1e9223372036854775808 wrapped to a
// negative exponent and compared as 1, so it was contained by the bound 100.
func TestDecimalContainmentRejectsExponentOverflow(t *testing.T) {
	for _, child := range []string{
		"1e9223372036854775808",
		"1e-9223372036854775808",
		"1e10001",
	} {
		if ok, reason := stringDomainCovers("decimal-string", "100", child); ok {
			t.Errorf("decimal-string 100 covers %q: ok=true reason=%q", child, reason)
		}
	}
	if ok, reason := stringDomainCovers("decimal-string", "100", "1e2"); !ok || reason != "" {
		t.Errorf("decimal-string 100 does not cover 1e2: ok=%v reason=%q", ok, reason)
	}
}

// TestStringDomainCoversDecimalRejectsNonCanonical checks the same rule through
// the domain entry point: a non-decimal operand is `invalid_params_binding`,
// never a value-space comparison.
func TestStringDomainCoversDecimalRejectsNonCanonical(t *testing.T) {
	for _, s := range []string{"3/2", "0x10", "1_000", "nan", ".5", "500."} {
		ok, reason := stringDomainCovers("decimal-string", "500", s)
		if ok || reason != "invalid_params_binding" {
			t.Errorf("stringDomainCovers(decimal-string, 500, %q) = (%v, %q), want (false, invalid_params_binding)",
				s, ok, reason)
		}
	}

	// Canonical forms still compare in value space.
	ok, reason := stringDomainCovers("decimal-string", "500", "500.00")
	if !ok || reason != "" {
		t.Errorf("stringDomainCovers(decimal-string, 500, 500.00) = (%v, %q), want (true, \"\")", ok, reason)
	}
}
