// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"strings"
	"testing"
)

func paymentType() ActionTypeDefinition {
	return ActionTypeDefinition{Type: "payment.release.1", MaterialFields: []string{"amount", "currency"}}
}

func paymentAction(amount, currency string, extra map[string]any) map[string]any {
	action := map[string]any{"amount": amount, "currency": currency}
	for k, v := range extra {
		action[k] = v
	}
	return action
}

// §4.2: only declared material fields enter the identity, and undeclared fields
// carry no action identity at all.
func TestComputeActionIDMaterialProjection(t *testing.T) {
	def := paymentType()
	plain, err := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", nil))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	if err := plain.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	withNoise, err := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", map[string]any{
		"memo": "lunch", "requested_at": "2026-09-13T12:00:00Z", "trace_id": "abc",
	}))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	if !plain.Digest.Equal(withNoise.Digest) {
		t.Error("an undeclared field changed the action identity")
	}

	// A different material value is a different action.
	other, err := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.01", "USD", nil))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	if plain.Digest.Equal(other.Digest) {
		t.Error("a different amount produced the same action identity")
	}

	// Determinism.
	again, err := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", nil))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	if !plain.Digest.Equal(again.Digest) || plain.String() != again.String() {
		t.Error("the same action produced a different identity")
	}

	// The projection is exactly the declared set.
	projection, err := MaterialProjection(def, paymentAction("100.00", "USD", map[string]any{"memo": "lunch"}))
	if err != nil {
		t.Fatalf("MaterialProjection: %v", err)
	}
	if len(projection) != 2 || projection["amount"] != "100.00" || projection["currency"] != "USD" {
		t.Errorf("projection = %v", projection)
	}
	if _, leaked := projection["memo"]; leaked {
		t.Error("an undeclared field leaked into the material projection")
	}

	// The suite set is closed: v1 defines jcs-sha256 only, so naming another
	// suite is a refusal rather than a computation.
	if _, err := ComputeActionID(def, ActionIdSuite("cbor-sha256"), paymentAction("100.00", "USD", nil)); !errors.Is(err, ErrActionSuite) {
		t.Errorf("an undefined suite was accepted: %v", err)
	}
}

// §4.2: a missing declared material field makes the action non-matchable —
// coverage is never inferred or defaulted.
func TestComputeActionIDMissingMaterialField(t *testing.T) {
	def := paymentType()
	if _, err := ComputeActionID(def, SuiteJCSSHA256, map[string]any{"amount": "100.00"}); !errors.Is(err, ErrActionNotMatchable) {
		t.Errorf("missing currency: got %v, want ErrActionNotMatchable", err)
	}
	if _, err := MaterialProjection(def, map[string]any{"currency": "USD"}); !errors.Is(err, ErrActionNotMatchable) {
		t.Errorf("MaterialProjection: got %v, want ErrActionNotMatchable", err)
	}
}

func TestComputeActionIDRejectsBadDefinitions(t *testing.T) {
	action := paymentAction("100.00", "USD", nil)
	cases := []struct {
		name  string
		def   ActionTypeDefinition
		suite ActionIdSuite
		want  error
	}{
		{"no type", ActionTypeDefinition{MaterialFields: []string{"a"}}, SuiteJCSSHA256, ErrActionShape},
		{"no material fields", ActionTypeDefinition{Type: "t"}, SuiteJCSSHA256, ErrActionShape},
		{"duplicate field", ActionTypeDefinition{Type: "t", MaterialFields: []string{"a", "a"}}, SuiteJCSSHA256, ErrActionShape},
		{"empty field name", ActionTypeDefinition{Type: "t", MaterialFields: []string{""}}, SuiteJCSSHA256, ErrActionShape},
		{"unknown suite", paymentType(), "jcs-md5", ErrActionSuite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ComputeActionID(tc.def, tc.suite, action); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestActionIdStringRoundTrip(t *testing.T) {
	id, err := ComputeActionID(paymentType(), SuiteJCSSHA256, paymentAction("100.00", "USD", nil))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	s := id.String()
	if !strings.HasPrefix(s, "clc-action:1:payment.release.1:jcs-sha256:") {
		t.Fatalf("identifier = %q", s)
	}
	back, err := ParseActionId(s)
	if err != nil {
		t.Fatalf("ParseActionId: %v", err)
	}
	if back.Type != id.Type || back.Suite != id.Suite || !back.Digest.Equal(id.Digest) {
		t.Fatalf("round trip changed the identity: %+v vs %+v", back, id)
	}

	for _, bad := range []string{
		"",
		"clc-action:2:payment.release.1:jcs-sha256:AAAA",
		"clc-action:1:payment.release.1:jcs-md5:AAAA",
		"clc-action:1::jcs-sha256:AAAA",
		"clc-action:1:payment.release.1:jcs-sha256:not base64!",
		// The CAID namespace is not ours to claim.
		"caid:1:payment.release.1:jcs-sha256:AAAA",
		"payment.release.1",
	} {
		if _, err := ParseActionId(bad); err == nil {
			t.Errorf("ParseActionId(%q) = nil error, want a refusal", bad)
		}
	}

	// Audit R15: the digest length is suite-pinned — a 4-byte base64url
	// digest must not be accepted under jcs-sha256 (it would round-trip
	// here without the length check).
	if _, err := ParseActionId("clc-action:1:payment.release.1:jcs-sha256:AAAA"); err == nil {
		t.Error("ParseActionId with 4-byte jcs-sha256 digest = nil error, want a refusal")
	}
}

// §6.4: equal identity matches; a comparable difference does not; anything the
// comparison cannot decide is indeterminate, never a match.
func TestMatchVerdicts(t *testing.T) {
	def := paymentType()
	base, err := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", nil))
	if err != nil {
		t.Fatalf("ComputeActionID: %v", err)
	}
	same, _ := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", map[string]any{"memo": "ignored"}))
	other, _ := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.01", "USD", nil))
	otherType, _ := ComputeActionID(ActionTypeDefinition{Type: "payment.refund.1", MaterialFields: []string{"amount", "currency"}},
		SuiteJCSSHA256, paymentAction("100.00", "USD", nil))

	cases := []struct {
		name     string
		observed ActionId
		evidence ActionId
		want     MatchVerdict
	}{
		{"identical", base, same, MatchExact},
		{"different amount", base, other, MatchNotEquivalent},
		{"different action type", base, otherType, MatchIndeterminate},
		{"unusable observed", ActionId{}, base, MatchIndeterminate},
		{"unusable evidence", base, ActionId{}, MatchIndeterminate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.observed, tc.evidence); got != tc.want {
				t.Fatalf("Match = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestMapAndMatch(t *testing.T) {
	def := paymentType()
	expected, _ := ComputeActionID(def, SuiteJCSSHA256, paymentAction("100.00", "USD", nil))
	foreign, _ := ComputeActionID(ActionTypeDefinition{Type: "psp.transfer.v3", MaterialFields: []string{"value", "ccy"}},
		SuiteJCSSHA256, map[string]any{"value": "100.00", "ccy": "USD"})

	pinned := ActionMappingProfile{ID: "varwof/payment-release@3", Digest: dg("profile-definition")}
	project := func(ActionMappingProfile, ActionId) (ActionId, error) { return expected, nil }

	if got := MapAndMatch(pinned, project, foreign, expected); got != MatchExact {
		t.Errorf("pinned profile with a faithful projection = %s, want MATCH", got)
	}

	// An unpinned profile establishes nothing.
	if got := MapAndMatch(ActionMappingProfile{ID: "varwof/payment-release@3"}, project, foreign, expected); got != MatchIndeterminate {
		t.Errorf("unpinned profile = %s, want INDETERMINATE", got)
	}
	if got := MapAndMatch(pinned, nil, foreign, expected); got != MatchIndeterminate {
		t.Errorf("no projector = %s, want INDETERMINATE", got)
	}
	// A lossy or failing projection is never a match.
	lossy := func(profile ActionMappingProfile, in ActionId) (ActionId, error) {
		return ActionId{}, ErrActionProjectionLossy
	}
	if got := MapAndMatch(pinned, lossy, foreign, expected); got != MatchIndeterminate {
		t.Errorf("lossy projection = %s, want INDETERMINATE", got)
	}
	// A projection into a different suite/type cannot be compared silently.
	wrongType := func(profile ActionMappingProfile, in ActionId) (ActionId, error) { return foreign, nil }
	if got := MapAndMatch(pinned, wrongType, foreign, expected); got != MatchIndeterminate {
		t.Errorf("projection into a foreign type = %s, want INDETERMINATE", got)
	}
	// A faithful projection of different content is a real inequality.
	different, _ := ComputeActionID(def, SuiteJCSSHA256, paymentAction("999.00", "USD", nil))
	projectDifferent := func(profile ActionMappingProfile, in ActionId) (ActionId, error) { return different, nil }
	if got := MapAndMatch(pinned, projectDifferent, foreign, expected); got != MatchNotEquivalent {
		t.Errorf("projected difference = %s, want NOT_EQUIVALENT", got)
	}
}

func TestMaterialFieldDigestIsDeterministic(t *testing.T) {
	def := paymentType()
	action := paymentAction("100.00", "USD", map[string]any{"memo": "ignored"})
	first, err := MaterialFieldDigest(def, action)
	if err != nil {
		t.Fatalf("MaterialFieldDigest: %v", err)
	}
	second, err := MaterialFieldDigest(def, action)
	if err != nil {
		t.Fatalf("MaterialFieldDigest: %v", err)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("unstable field digests: %v vs %v", first, second)
	}
	if len(first) != 2 || !strings.HasPrefix(first[0], "amount:") {
		t.Fatalf("field digests = %v", first)
	}
	for _, d := range first {
		if strings.Contains(d, "memo") {
			t.Errorf("undeclared field appeared in the field digests: %v", first)
		}
	}
}
