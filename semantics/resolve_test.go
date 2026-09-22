// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"slices"
	"testing"
)

const (
	resolveNet  = `varwof/constraint-v1:network:cidr:["192.0.2.0/24"]`
	resolveNet2 = `varwof/constraint-v1:network:cidr:["2001:db8::/32"]`
	resolveWin  = `varwof/constraint-v1:time:window:[{"start":"22:00","end":"00:00"}]`
)

func TestResolveTerminalPassThrough(t *testing.T) {
	deny := Decision{Verdict: VerdictDeny, Reason: "capability_not_authorized"}
	res := []Resolution{{Constraint: resolveNet, Status: ResolutionSatisfied}}
	if got := Resolve(deny, res, ""); got.Verdict != VerdictDeny || got.Reason != "capability_not_authorized" {
		t.Fatalf("deny revived: %+v", got)
	}
	allow := Decision{Verdict: VerdictAllow}
	if got := Resolve(allow, res, "2026-09-21T22:30:00Z"); got.Verdict != VerdictAllow {
		t.Fatalf("allow changed: %+v", got)
	}
}

func TestResolveDischarge(t *testing.T) {
	d := Decision{Verdict: VerdictAllowUR, Unresolved: []string{resolveNet, resolveNet2}}

	if got := Resolve(d, []Resolution{
		{Constraint: resolveNet, Status: ResolutionSatisfied},
		{Constraint: resolveNet2, Status: ResolutionSatisfied},
	}, ""); got.Verdict != VerdictAllow {
		t.Fatalf("all satisfied: got %+v", got)
	}

	got := Resolve(d, []Resolution{{Constraint: resolveNet, Status: ResolutionSatisfied}}, "")
	if got.Verdict != VerdictAllowUR || !slices.Equal(got.Unresolved, []string{resolveNet2}) {
		t.Fatalf("partial: got %+v", got)
	}

	got = Resolve(d, []Resolution{{Constraint: resolveNet, Status: ResolutionViolated}}, "")
	if got.Verdict != VerdictDeny || got.Reason != "network:violated" {
		t.Fatalf("violated: got %+v", got)
	}
}

func TestResolveConflictAndUnrelated(t *testing.T) {
	d := Decision{Verdict: VerdictAllowUR, Unresolved: []string{resolveNet}}
	got := Resolve(d, []Resolution{
		{Constraint: resolveNet, Status: ResolutionSatisfied},
		{Constraint: resolveNet, Status: ResolutionViolated},
	}, "")
	if got.Verdict != VerdictDeny {
		t.Fatalf("violated must dominate satisfied: %+v", got)
	}
	got = Resolve(d, []Resolution{{Constraint: resolveNet2, Status: ResolutionSatisfied}}, "")
	if got.Verdict != VerdictAllowUR || !slices.Equal(got.Unresolved, []string{resolveNet}) {
		t.Fatalf("unrelated resolution must be ignored: %+v", got)
	}
}

func TestResolveCoreClockTTL(t *testing.T) {
	d := Decision{Verdict: VerdictAllowUR, Unresolved: []string{resolveWin}}

	if got := Resolve(d, nil, "2026-09-21T22:30:00Z"); got.Verdict != VerdictAllow {
		t.Fatalf("in window: %+v", got)
	}
	if got := Resolve(d, nil, "2026-09-21T22:00:00Z"); got.Verdict != VerdictAllow {
		t.Fatalf("start inclusive: %+v", got)
	}
	if got := Resolve(d, nil, "2026-09-21T23:59:59Z"); got.Verdict != VerdictAllow {
		t.Fatalf("just before end: %+v", got)
	}
	got := Resolve(d, nil, "2026-09-22T00:00:00Z")
	if got.Verdict != VerdictDeny || got.Reason != "time:violated" {
		t.Fatalf("end exclusive (TTL expiry): %+v", got)
	}
	// A stale satisfied report cannot outlive the window.
	got = Resolve(d, []Resolution{{Constraint: resolveWin, Status: ResolutionSatisfied}}, "2026-09-22T00:00:00Z")
	if got.Verdict != VerdictDeny || got.Reason != "time:violated" {
		t.Fatalf("stale report override: %+v", got)
	}
	// Without now, a report is accepted (no core TTL).
	if got := Resolve(d, []Resolution{{Constraint: resolveWin, Status: ResolutionSatisfied}}, ""); got.Verdict != VerdictAllow {
		t.Fatalf("no-now assertion: %+v", got)
	}
	// Without now and without a report, it stays unresolved.
	if got := Resolve(d, nil, ""); got.Verdict != VerdictAllowUR {
		t.Fatalf("no-now unknown: %+v", got)
	}
}

func TestResolveMalformed(t *testing.T) {
	d := Decision{Verdict: VerdictAllowUR, Unresolved: []string{resolveNet}}
	if got := Resolve(d, []Resolution{{Constraint: resolveNet, Status: "maybe"}}, ""); got.Verdict != VerdictDeny || got.Reason != "invalid_resolution" {
		t.Fatalf("bad status: %+v", got)
	}
	if got := Resolve(d, []Resolution{{Constraint: "", Status: ResolutionSatisfied}}, ""); got.Verdict != VerdictDeny || got.Reason != "invalid_resolution" {
		t.Fatalf("empty constraint: %+v", got)
	}
	if got := Resolve(d, nil, "not-a-time"); got.Verdict != VerdictDeny || got.Reason != "invalid_timestamp" {
		t.Fatalf("bad now: %+v", got)
	}
}

func TestResolveIdempotent(t *testing.T) {
	d := Decision{Verdict: VerdictAllowUR, Unresolved: []string{resolveNet, resolveNet2}}
	res := []Resolution{{Constraint: resolveNet, Status: ResolutionSatisfied}}
	once := Resolve(d, res, "")
	twice := Resolve(once, res, "")
	if once.Verdict != twice.Verdict || !slices.Equal(once.Unresolved, twice.Unresolved) {
		t.Fatalf("not idempotent: %+v vs %+v", once, twice)
	}
}
