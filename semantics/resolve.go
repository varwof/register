// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Resolve — the residual-obligation consumer loop (CLC §8.5, rev CLC-1.11).
//
// §8.4 delivers obligations on an allow_unresolved verdict but leaves the
// consumer's feedback loop undefined.  Resolve closes it: a consumer reports,
// per obligation, satisfied / violated / unknown, and the core collapses the
// result to a fresh decision.  The sources combine most-restrictive-first
// (violated ≻ satisfied ≻ unknown), and supplying a clock (`now`) makes the
// core evaluate a time:window obligation directly — the TTL of its discharge
// is the end of the segment containing now.

package semantics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// ResolutionSatisfied / ResolutionViolated / ResolutionUnknown are the
	// three §8.5 resolution statuses.
	ResolutionSatisfied = "satisfied"
	ResolutionViolated  = "violated"
	ResolutionUnknown   = "unknown"
)

var (
	// ErrInvalidResolution / ErrInvalidTimestamp are the §8.5 input-error
	// reason codes.
	ErrInvalidResolution = errors.New("invalid_resolution")
	ErrInvalidTimestamp  = errors.New("invalid_timestamp")
)

// Resolution is a consumer's per-obligation report to Resolve (§8.5).
type Resolution struct {
	Constraint string `json:"constraint"`
	Status     string `json:"status"`
}

// Resolve collapses a decision's §8.4 obligations with a consumer's reports
// and an optional clock (§8.5).  now is an RFC3339 UTC instant, "" for absent.
//
// It is deterministic, fail-closed, idempotent and monotone; it neither
// invents nor drops obligations.  Terminal deny/allow decisions pass through
// unchanged.
func Resolve(d Decision, resolutions []Resolution, now string) Decision {
	// Rule 1: terminal verdicts are fixed.
	if d.Verdict == VerdictDeny || d.Verdict == VerdictAllow {
		return d
	}
	if d.Verdict != VerdictAllowUR {
		// Any other verdict value is not a §8.4 decision; refuse it closed.
		return Decision{Verdict: VerdictDeny, Reason: ErrInvalidResolution.Error()}
	}

	// Rule 2: malformed input fails closed, before any discharge.
	for _, r := range resolutions {
		if r.Constraint == "" || !validResolutionStatus(r.Status) {
			return Decision{Verdict: VerdictDeny, Reason: ErrInvalidResolution.Error()}
		}
	}
	var nowTime time.Time
	if now != "" {
		t, err := time.Parse(time.RFC3339, now)
		if err != nil {
			return Decision{Verdict: VerdictDeny, Reason: ErrInvalidTimestamp.Error()}
		}
		nowTime = t.UTC()
	}

	// Rule 3-5: status per obligation, most-restrictive-first.
	obligations := sortedSet(d.Unresolved)
	remainder := make([]string, 0, len(obligations))
	for _, o := range obligations {
		status := ResolutionUnknown
		for _, r := range resolutions {
			if r.Constraint == o {
				status = stricterStatus(status, r.Status)
			}
		}
		if now != "" {
			if ok, satisfied := evalCoreTimeWindow(o, nowTime); ok && !satisfied {
				status = stricterStatus(status, ResolutionViolated)
			} else if ok && satisfied {
				status = stricterStatus(status, ResolutionSatisfied)
			}
		}
		switch status {
		case ResolutionViolated:
			// Rule 6: any violated → deny with {type}:violated of the first
			// violated obligation in canonical (sorted) order.
			return Decision{Verdict: VerdictDeny, Reason: violatedReason(o)}
		case ResolutionSatisfied:
			// discharged
		default:
			remainder = append(remainder, o)
		}
	}

	// Rule 6: all satisfied → allow; otherwise the unknown remainder.
	if len(remainder) == 0 {
		return Decision{Verdict: VerdictAllow}
	}
	return Decision{Verdict: VerdictAllowUR, Unresolved: remainder}
}

func validResolutionStatus(s string) bool {
	switch s {
	case ResolutionSatisfied, ResolutionViolated, ResolutionUnknown:
		return true
	}
	return false
}

// stricterStatus returns the more restrictive of two §8.5 statuses under
// violated ≻ satisfied ≻ unknown (fail-closed).
func stricterStatus(a, b string) string {
	rank := func(s string) int {
		switch s {
		case ResolutionViolated:
			return 2
		case ResolutionSatisfied:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// violatedReason returns a constraint's {type}:violated code — the §9.2
// convention, e.g. `time:violated`, `network:violated`.
func violatedReason(c string) string {
	parts := strings.Split(c, ":")
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1] + ":violated"
	}
	// A constraint without a parseable type cannot name a code; this is
	// unreachable for core decisions, but fall back to the generic identity.
	return "violated"
}

// evalCoreTimeWindow reports whether c is a core-recognized §8.1 time:window
// obligation, and if so whether now falls inside it (half-open [start,end),
// UTC, daily-repeating).  ok=false means "not core-evaluable".
func evalCoreTimeWindow(c string, now time.Time) (ok, satisfied bool) {
	if ValidateConstraint(c) != nil {
		return false, false
	}
	parts := strings.Split(c, ":")
	if len(parts) < 2 || parts[0]+":"+parts[1] != reservedTimeWin {
		return false, false
	}
	joined := constraintParams(c)
	if !strings.HasPrefix(joined, "window:") {
		return false, false
	}
	raw := strings.TrimPrefix(joined, "window:")
	segments, err := parseTimeWindow(raw)
	if err != nil {
		return false, false
	}
	sod := now.Hour()*3600 + now.Minute()*60 + now.Second()
	for _, seg := range segments {
		if sod >= seg[0] && sod < seg[1] {
			return true, true
		}
	}
	return true, false
}

// parseTimeWindow parses a §8.1 window array into [startSod, endSod) pairs,
// where an end of "00:00" is next-day midnight (86400).  The input is assumed
// to have passed validTimeWindowJSON; malformed input yields an error.
func parseTimeWindow(raw string) ([][2]int, error) {
	var segments []map[string]string
	if err := jsonUnmarshalStrict(raw, &segments); err != nil {
		return nil, err
	}
	out := make([][2]int, 0, len(segments))
	for _, s := range segments {
		start, okS := s["start"]
		end, okE := s["end"]
		if !okS || !okE {
			return nil, fmt.Errorf("%w: malformed window segment", ErrInvalidConstraint)
		}
		startSod := secondsOfDay(start)
		endSod := secondsOfDay(end)
		if end == "00:00" {
			endSod = 86400
		}
		out = append(out, [2]int{startSod, endSod})
	}
	return out, nil
}

// jsonUnmarshalStrict decodes JSON into v, rejecting trailing content.
func jsonUnmarshalStrict(raw string, v any) error {
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing content")
	}
	return nil
}
