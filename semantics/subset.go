// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	pki "github.com/varwof/types"
)

// canonicalConstraintScheme maps the constraint namespace aliases accepted on
// the wire to the one canonical CLC scheme.  Core's AIC extension writer and
// the verifier glue both accept "constraint" / "constraint-v1" as legacy
// aliases for "varwof/constraint-v1"; the shared language must do the same,
// otherwise a principal certificate written with an alias fails the subset
// check even though every other layer understood it.
func canonicalConstraintScheme(scheme string) (string, bool) {
	switch scheme {
	case reservedScheme, "constraint", "constraint-v1":
		return reservedScheme, true
	default:
		return "", false
	}
}

// CanonicalConstraint normalizes a constraint capability's scheme to the
// canonical CLC form "varwof/constraint-v1", accepting the legacy aliases
// "constraint" and "constraint-v1".  Non-constraint capabilities are returned
// unchanged.  Producers (the DA signer and the CA AIC writer) SHOULD
// canonicalize the effective set before signing/writing so the persisted form
// is always the spec-recommended one, independent of what alias was supplied.
func CanonicalConstraint(c pki.Capability) pki.Capability {
	if scheme, ok := canonicalConstraintScheme(c.SchemeId); ok {
		c.SchemeId = scheme
	}
	return c
}

// CanonicalConstraints canonicalizes every entry in place-safe fashion.
func CanonicalConstraints(caps []pki.Capability) []pki.Capability {
	if caps == nil {
		return nil
	}
	out := make([]pki.Capability, len(caps))
	for i, c := range caps {
		out[i] = CanonicalConstraint(c)
	}
	return out
}

// ConstraintString renders a single authorization constraint capability in the
// canonical CLC-v1 constraint-string form (§8.1): "scheme:id:value".  The
// reserved varwof/constraint-v1 scheme is accepted together with its legacy
// aliases "constraint" and "constraint-v1" (canonicalised on output); any other
// scheme is not a recognized CLC constraint and fails closed with
// unknown_constraint.
//
// The wire Parameters already carry the §8.1 value grammar (max_rows: a strict
// JSON integer; time/network: the JSON array after the type crumb), so the
// string is exactly scheme + ":" + id + ":" + value.  It round-trips
// byte-for-byte with ValidateConstraint, which makes the string the canonical
// intermediate form both the DA signer and the CA reconstruction derive the
// same effective set from (the "two sides must call the same function" rule).
func ConstraintString(c pki.Capability) (string, error) {
	scheme, ok := canonicalConstraintScheme(c.SchemeId)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownConstraint, c.SchemeId)
	}
	if c.CapabilityId == "" {
		return "", fmt.Errorf("%w: empty constraint id", ErrInvalidConstraint)
	}
	s := scheme + ":" + c.CapabilityId + ":" + string(c.Parameters)
	if err := ValidateConstraint(s); err != nil {
		return "", err
	}
	return s, nil
}

// SubsetConstraints reports whether every requested constraint falls inside the
// principal's boundary constraints.  Entries are the canonical CLC constraint
// strings produced by ConstraintString.
//
//   - principal empty → the principal declares no boundary: any requested set
//     is within it (each requested string is still validated).
//   - requested empty → trivially true; the caller inherits the principal set
//     in full (§继承语义).
//   - requested contains a type the principal does not bound, or a value
//     outside the boundary → false (deny: the agent would widen its own grant).
//   - unknown / malformed type on either side → error (fail closed): a
//     boundary the core cannot understand must not be silently relied on.
//
// Per-type containment:
//
//	max_rows    requested ≤ principal (numeric)
//	time:window every requested daily segment lies inside one principal
//	            segment (same-day segments; end "00:00" is next-day midnight)
//	network:cidr every requested network is inside a principal network of the
//	            same address family (v4/v6 never mixed)
func SubsetConstraints(principal, requested []string) (bool, error) {
	// No requested constraints: full inheritance, nothing to verify.
	if len(requested) == 0 {
		return true, nil
	}
	rBound, err := groupByConstraintType(requested)
	if err != nil {
		return false, err
	}
	// Principal declares no boundary: any requested set is within it, but the
	// requested set itself is still validated above (fail-closed on junk).
	if len(principal) == 0 {
		return true, nil
	}
	pBound, err := groupByConstraintType(principal)
	if err != nil {
		return false, err
	}
	for id, rset := range rBound {
		pset, ok := pBound[id]
		if !ok {
			// The principal does not bound this class at all; the request
			// widens the grant beyond the documented upper bound.
			return false, nil
		}
		if !subsetOfType(id, rset, pset) {
			return false, nil
		}
	}
	return true, nil
}

// constraintTypeOf returns the recognized (scheme,type) identity of a CLC
// constraint string, validating the whole value grammar on the way (§8.1).
func constraintTypeOf(s string) (string, error) {
	if err := ValidateConstraint(s); err != nil {
		return "", err
	}
	parts := strings.SplitN(s, ":", 3)
	return parts[0] + ":" + parts[1], nil
}

// groupByConstraintType validates every entry and groups it by its recognized
// (scheme,type) identity.
func groupByConstraintType(list []string) (map[string][]string, error) {
	out := make(map[string][]string)
	for _, s := range list {
		id, err := constraintTypeOf(s)
		if err != nil {
			return nil, err
		}
		out[id] = append(out[id], s)
	}
	return out, nil
}

// subsetOfType compares two value sets of the same constraint identity:
// every requested value must be inside at least one principal value.
func subsetOfType(id string, requested, principal []string) bool {
	switch id {
	case reservedMaxRows:
		pMax := -1
		for _, s := range principal {
			if n := maxRowsValue(s); n > pMax {
				pMax = n
			}
		}
		for _, s := range requested {
			if maxRowsValue(s) > pMax {
				return false
			}
		}
		return true
	case reservedTimeWin:
		for _, r := range requested {
			rs := timeWindowSegments(r)
			renderred := false
			for _, ps := range principal {
				if windowContains(timeWindowSegments(ps), rs) {
					renderred = true
					break
				}
			}
			if !renderred {
				return false
			}
		}
		return true
	case reservedNetCIDR:
		var pl []netip.Prefix
		for _, s := range principal {
			pl = append(pl, cidrPrefixes(s)...)
		}
		for _, r := range requested {
			for _, rp := range cidrPrefixes(r) {
				if !inAnyNetwork(rp, pl) {
					return false
				}
			}
		}
		return true
	}
	// Unreachable via groupByConstraintType, but stay fail-closed.
	return false
}

// maxRowsValue extracts the strict-JSON-integer value of a max_rows
// constraint string.  The caller has already passed ValidateConstraint, so the
// extraction cannot fail.
func maxRowsValue(s string) int {
	parts := strings.Split(s, ":")
	n := 0
	for i := 0; i < len(parts[2]); i++ {
		n = n*10 + int(parts[2][i]-'0')
	}
	return n
}

// windowRange is a half-open [startSec, endSec) seconds-of-day span.
type windowRange struct{ start, end int }

// timeWindowSegments decodes the §8.1 window:value into half-open second-of-day
// spans.  "end":"00:00" is the reserved next-day midnight (86400).
func timeWindowSegments(s string) []windowRange {
	var raw []struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	value := strings.TrimPrefix(constraintParams(s), "window:")
	_ = json.Unmarshal([]byte(value), &raw)
	out := make([]windowRange, 0, len(raw))
	for _, seg := range raw {
		out = append(out, windowRange{
			start: secondsOfDay(seg.Start),
			end:   secondsOfDay(seg.End),
		})
		if seg.End == "00:00" {
			out[len(out)-1].end = 86400
		}
	}
	return out
}

// windowContains reports whether every span of r lies inside at least one span
// of p.  Containment is per principal segment — a requested segment is covered
// only when a single principal segment spans it (cross-segment coverage is not
// allowed).
func windowContains(p, r []windowRange) bool {
	for _, rw := range r {
		covered := false
		for _, pw := range p {
			if pw.start <= rw.start && rw.end <= pw.end {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// cidrPrefixes decodes the §8.1 cidr:value into parsed network prefixes.
func cidrPrefixes(s string) []netip.Prefix {
	value := strings.TrimPrefix(constraintParams(s), "cidr:")
	var list []string
	if err := json.Unmarshal([]byte(value), &list); err != nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, e := range list {
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// inAnyNetwork reports whether network r is fully contained in at least one
// member of networks.  v4 and v6 are never mixed.
func inAnyNetwork(r netip.Prefix, networks []netip.Prefix) bool {
	for _, p := range networks {
		if p.Addr().BitLen() != r.Addr().BitLen() {
			continue
		}
		if p.Bits() > r.Bits() {
			continue
		}
		if p.Contains(r.Addr()) {
			return true
		}
	}
	return false
}
