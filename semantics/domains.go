// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Declared parameter domains (CLC-1.19 §6.7).
//
// The declaration is applied as a pre-comparison normalization: a value whose
// domain has a numeric normal form is rewritten into that form, and the
// ordinary relations then run unchanged.  `quantity` is normalized to its
// number; the three string-shaped domains (`decimal-string`, `subdomain`,
// `path-prefix`) are decided in the *WithDomains pre-check and then neutralized
// so the ordinary relation does not re-compare them by shape.  A domain name
// the revision does not define is refused with `unsupported_domain`.
package semantics

import (
	"errors"
	"math"
	"math/big"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// decimalLiteral is the canonical `decimal-string` grammar: a signed integer
// part, an optional fractional part, and an optional exponent.  It deliberately
// excludes the extra forms big.Rat.SetString accepts (fractions "a/b",
// hexadecimal "0x..", digit separators "1_000") per §6.7.
var decimalLiteral = regexp.MustCompile(`^[+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// DomainSpec is one parameter's declared domain.
type DomainSpec struct {
	Name string
	Unit string // fixed for quantity; empty otherwise
}

// DomainMap maps a parameter name to its declaration.
type DomainMap map[string]DomainSpec

// NormalizeForDomains rewrites every declared quantity value into its
// normalized number.  It returns a canonical reason code when a value cannot
// be normalized or the declared domain is not defined by the revision.
func NormalizeForDomains(params map[string]any, dm DomainMap) (map[string]any, string) {
	if len(dm) == 0 || len(params) == 0 {
		return params, ""
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		spec, ok := dm[k]
		if !ok {
			out[k] = v
			continue
		}
		switch spec.Name {
		case "bound", "enum", "exact":
			out[k] = v // shape-inferred, unchanged
		case "decimal-string", "subdomain", "path-prefix":
			// Decided by the *WithDomains pre-check; the value passes through
			// here (possibly already neutralized) for the ordinary relation.
			out[k] = v
		case "quantity":
			n, reason := quantityNumber(v, spec.Unit)
			if reason != "" {
				return nil, reason
			}
			out[k] = n
		default:
			// A domain name the revision does not define: fail closed.
			return nil, "unsupported_domain"
		}
	}
	return out, ""
}

func quantityNumber(v any, unit string) (float64, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return 0, "invalid_params_binding"
	}
	val, ok := numberValue(m["value"])
	if !ok {
		return 0, "invalid_params_binding"
	}
	u, _ := m["unit"].(string)
	if u == "" {
		return 0, "invalid_params_binding"
	}
	if u != unit {
		return 0, "unit_mismatch"
	}
	scale := 0
	if s, ok := m["scale"]; ok {
		f, ok := numberValue(s)
		if !ok || f != math.Trunc(f) {
			return 0, "invalid_params_binding"
		}
		scale = int(f)
	}
	return val * math.Pow10(-scale), ""
}

func numberValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// EntailsWithDomains applies the declaration and then the ordinary entailment.
func EntailsWithDomains(g Grant, op Operation, dm DomainMap) MatchResult {
	for name, spec := range dm {
		switch spec.Name {
		case "decimal-string", "subdomain", "path-prefix":
			gv, gok := g.Params[name]
			ov, ook := op.Params[name]
			if !gok || !ook {
				continue
			}
			ok, reason := stringDomainCovers(spec.Name, gv, ov)
			if !ok {
				return MatchResult{Reason: reason}
			}
			g.Params = neutralize(g.Params, name)
			op.Params = neutralize(op.Params, name)
		}
	}
	gp, reason := NormalizeForDomains(g.Params, dm)
	if reason != "" {
		return MatchResult{Reason: reason}
	}
	opp, reason := NormalizeForDomains(op.Params, dm)
	if reason != "" {
		return MatchResult{Reason: reason}
	}
	g.Params, op.Params = gp, opp
	return Entails(g, op)
}

// AuthorizeSetWithDomains applies one declaration to every grant and to the
// operation, then runs the ordinary multi-grant aggregation.
func AuthorizeSetWithDomains(grants []Grant, op Operation, dm DomainMap) Decision {
	opParams := copyParams(op.Params)
	norm := make([]Grant, 0, len(grants))
	for _, g := range grants {
		if declaredBoundConflict(g, dm) {
			return Decision{Verdict: VerdictDeny, Reason: "invalid_params_binding"}
		}
		usable := true
		gp := copyParams(g.Params)
		for name, spec := range dm {
			switch spec.Name {
			case "decimal-string", "subdomain", "path-prefix":
				gv, gok := gp[name]
				ov, ook := opParams[name]
				if !gok || !ook {
					continue
				}
				ok, reason := stringDomainCovers(spec.Name, gv, ov)
				if !ok {
					if reason == "invalid_params_binding" {
						return Decision{Verdict: VerdictDeny, Reason: reason}
					}
					usable = false
					break
				}
				gp = neutralize(gp, name)
				opParams = neutralize(opParams, name)
			}
		}
		if !usable {
			continue
		}
		np, reason := NormalizeForDomains(gp, dm)
		if reason != "" {
			return Decision{Verdict: VerdictDeny, Reason: reason}
		}
		g.Params = np
		norm = append(norm, g)
	}
	if len(norm) == 0 && len(grants) > 0 {
		return Decision{Verdict: VerdictDeny, Reason: "params_exceed_grant"}
	}
	opp, reason := NormalizeForDomains(opParams, dm)
	if reason != "" {
		return Decision{Verdict: VerdictDeny, Reason: reason}
	}
	op.Params = opp
	return AuthorizeSet(norm, op)
}

func copyParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

// ContainsWithDomains applies the parent's and child's declarations and then
// the ordinary containment relation.  A value that cannot be normalized under
// its declared domain is not comparable, so containment fails closed with
// `params_not_narrower`.
func ContainsWithDomains(parent, child Grant, parentDom, childDom DomainMap) ContainmentResult {
	if declaredBoundConflict(parent, parentDom) || declaredBoundConflict(child, childDom) {
		return ContainmentResult{Contains: false, Reason: "params_not_narrower"}
	}
	// String-shaped declared domains are compared here, then neutralized so the
	// ordinary relation does not compare them again by shape.
	for name, pspec := range parentDom {
		cspec, ok := childDom[name]
		if !ok {
			continue
		}
		if pspec.Name != cspec.Name {
			return ContainmentResult{Contains: false, Reason: "params_not_narrower"}
		}
		switch pspec.Name {
		case "decimal-string", "subdomain", "path-prefix":
			pv, pok := parent.Params[name]
			cv, cok := child.Params[name]
			if !pok || !cok {
				continue // key-set rules decide
			}
			ok, _ := stringDomainCovers(pspec.Name, pv, cv)
			if !ok {
				return ContainmentResult{Contains: false, Reason: "params_not_narrower"}
			}
			parent.Params = neutralize(parent.Params, name)
			child.Params = neutralize(child.Params, name)
		}
	}
	pp, reason := NormalizeForDomains(parent.Params, parentDom)
	if reason != "" {
		return ContainmentResult{Contains: false, Reason: "params_not_narrower"}
	}
	cp, reason := NormalizeForDomains(child.Params, childDom)
	if reason != "" {
		return ContainmentResult{Contains: false, Reason: "params_not_narrower"}
	}
	parent.Params, child.Params = pp, cp
	return Contains(parent, child)
}

// declaredBoundConflict reports whether a grant declares a parameter in
// param_bounds whose domain is declared in the scheme declaration.  Such a key
// has one comparison rule (the declaration) and must not also carry a Bound
// family (§6.7).
func declaredBoundConflict(g Grant, dm DomainMap) bool {
	for name := range g.ParamBounds {
		if _, ok := dm[name]; ok {
			return true
		}
	}
	return false
}

// neutralize replaces one parameter with a fixed scalar so the ordinary
// relation sees equal values for a domain it has already decided.
func neutralize(params map[string]any, name string) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	out[name] = "domain-covered"
	return out
}

// stringDomainCovers decides whether parent covers child for one string-shaped
// declared domain.
func stringDomainCovers(domain string, parent, child any) (bool, string) {
	p, ok := parent.(string)
	if !ok {
		return false, "invalid_params_binding"
	}
	c, ok := child.(string)
	if !ok {
		return false, "invalid_params_binding"
	}
	switch domain {
	case "decimal-string":
		pr, ok1 := parseDecimal(p)
		cr, ok2 := parseDecimal(c)
		if !ok1 || !ok2 {
			return false, "invalid_params_binding"
		}
		if cr.Cmp(pr) > 0 {
			return false, "params_exceed_grant"
		}
		return true, ""
	case "subdomain":
		pp := normalizeDomainName(p)
		cc := normalizeDomainName(c)
		if pp == "" || cc == "" {
			return false, "invalid_params_binding"
		}
		if cc == pp || strings.HasSuffix(cc, "."+pp) {
			return true, ""
		}
		return false, "params_exceed_grant"
	case "path-prefix":
		if !strings.HasPrefix(p, "/") || !strings.HasPrefix(c, "/") {
			return false, "invalid_params_binding"
		}
		// A path that is not already clean is refused rather than reinterpreted.
		if path.Clean(p) != p || path.Clean(c) != c {
			return false, "invalid_params_binding"
		}
		if c == p || strings.HasPrefix(c, strings.TrimSuffix(p, "/")+"/") {
			return true, ""
		}
		return false, "params_exceed_grant"
	}
	return false, "unsupported_domain"
}

// normalizeDomainName lowercases a DNS name and strips one trailing dot.
func normalizeDomainName(s string) string {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return ""
		}
	}
	return s
}

// Decimal literals are bounded so an untrusted exponent cannot turn a value
// comparison into an unbounded big.Int allocation.  The bound is far above any
// practical CLC parameter while keeping 10^exp cheap.
const (
	maxDecimalExponent = 10000
	maxDecimalMantissa = 10000
)

// parseDecimal parses a decimal string (optionally with an exponent) into an
// exact rational, so value-space comparison never goes through float64.
func parseDecimal(s string) (*big.Rat, bool) {
	if !decimalLiteral.MatchString(s) {
		return nil, false
	}
	mantissa, exp := s, 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa = s[:i]
		e, err := parseIntStrict(s[i+1:])
		if err != nil {
			return nil, false
		}
		exp = e
	}
	if len(mantissa) > maxDecimalMantissa {
		return nil, false
	}
	r := new(big.Rat)
	if _, ok := r.SetString(mantissa); !ok {
		return nil, false
	}
	if exp == 0 {
		return r, true
	}
	negExp := exp < 0
	if negExp {
		exp = -exp // safe: parseIntStrict bounds exp to +/-maxDecimalExponent
	}
	pow := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exp)), nil)
	if negExp {
		r.Quo(r, new(big.Rat).SetInt(pow))
	} else {
		r.Mul(r, new(big.Rat).SetInt(pow))
	}
	return r, true
}

func parseIntStrict(s string) (int, error) {
	if s == "" {
		return 0, strconvErr()
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, strconvErr()
	}
	if n < -maxDecimalExponent || n > maxDecimalExponent {
		return 0, strconvErr()
	}
	return int(n), nil
}

func strconvErr() error { return errors.New("invalid exponent") }
