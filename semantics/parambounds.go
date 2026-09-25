package semantics

import (
	"fmt"
	"math"
	"sort"
)

// This file implements the extended parameter bounds of CLC-v1 §6.5
// (rev CLC-1.10): an optional grant field `param_bounds` carrying inclusive
// min/max, a step multiple rule, an enum with cardinality bounds, an optional
// key marker and nested recursion.  It is strictly additive: a grant without
// `param_bounds` follows the existing §6.2 path unchanged.

// boundOptional reports whether a Bound object marks its key optional
// (default false, i.e. required).
func boundOptional(b any) bool {
	m, ok := b.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m["optional"].(bool)
	return ok && v
}

// ValidateParamBounds checks the §6.5 bound grammar and the one-representation
// binding rule: a key MUST NOT be declared in both params and param_bounds,
// every Bound is a closed object with at most one value family, and its
// members are well-typed.
func ValidateParamBounds(bounds, params map[string]any) error {
	if bounds == nil {
		return nil
	}
	if err := validateObjectParams(bounds); err != nil {
		return err
	}
	for k, b := range bounds {
		if k == "" {
			return fmt.Errorf("%w: empty key", ErrInvalidParamsBinding)
		}
		if _, dup := params[k]; dup {
			return fmt.Errorf("%w: %s in both params and param_bounds", ErrInvalidParamsBinding, k)
		}
		if err := validateBound(b); err != nil {
			return err
		}
	}
	return nil
}

func validateBound(b any) error {
	m, ok := b.(map[string]any)
	if !ok {
		return ErrInvalidParamsBinding
	}
	hasNumeric, hasEnum, hasNested := false, false, false
	for k := range m {
		switch k {
		case "min", "max", "step":
			hasNumeric = true
		case "enum", "min_items", "max_items":
			hasEnum = true
		case "nested":
			hasNested = true
		case "optional":
			if _, ok := m[k].(bool); !ok {
				return fmt.Errorf("%w: optional is not a boolean", ErrInvalidParamsBinding)
			}
		default:
			return fmt.Errorf("%w: unknown Bound member %q", ErrInvalidParamsBinding, k)
		}
	}
	families := 0
	if hasNumeric {
		families++
	}
	if hasEnum {
		families++
	}
	if hasNested {
		families++
	}
	if families > 1 {
		return fmt.Errorf("%w: mixed bound families", ErrInvalidParamsBinding)
	}
	for _, k := range []string{"min", "max", "step"} {
		if v, ok := m[k]; ok {
			if _, ok := v.(float64); !ok {
				return fmt.Errorf("%w: %s is not a number", ErrInvalidParamsBinding, k)
			}
		}
	}
	if st, ok := m["step"].(float64); ok && st <= 0 {
		return fmt.Errorf("%w: step must be positive", ErrInvalidParamsBinding)
	}
	if mn, ok := m["min"].(float64); ok {
		if mx, ok := m["max"].(float64); ok && mn > mx {
			return fmt.Errorf("%w: min > max", ErrInvalidParamsBinding)
		}
	}
	if v, ok := m["enum"]; ok {
		if _, ok := v.([]any); !ok {
			return fmt.Errorf("%w: enum is not an array", ErrInvalidParamsBinding)
		}
	}
	for _, k := range []string{"min_items", "max_items"} {
		if v, ok := m[k]; ok {
			n, ok := v.(float64)
			if !ok || n < 0 || n != math.Trunc(n) {
				return fmt.Errorf("%w: %s is not a non-negative integer", ErrInvalidParamsBinding, k)
			}
		}
	}
	if mn, ok := m["min_items"].(float64); ok {
		if mx, ok := m["max_items"].(float64); ok && mn > mx {
			return fmt.Errorf("%w: min_items > max_items", ErrInvalidParamsBinding)
		}
	}
	if v, ok := m["nested"]; ok {
		nm, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: nested is not an object", ErrInvalidParamsBinding)
		}
		for _, nb := range nm {
			if err := validateBound(nb); err != nil {
				return err
			}
		}
	}
	return nil
}

// grantDeclaredKeys is the §6.5 declared key set: keys(params) ∪ keys(param_bounds).
func grantDeclaredKeys(g Grant) map[string]bool {
	set := map[string]bool{}
	for k := range g.Params {
		set[k] = true
	}
	for k := range g.ParamBounds {
		set[k] = true
	}
	return set
}

// entailsDeclared is the §6.5-aware replacement for the §6.2 paramsSubset
// comparison in Entails: it implements layers 5-9 over the §6.5 declared key
// set (keys(params) ∪ keys(param_bounds)), honouring the optional marker and
// the bound value families.  For a grant with no param_bounds it reproduces
// the original paramsSubset behaviour exactly.
func entailsDeclared(opParams, grantParams, grantBounds map[string]any) (bool, string) {
	// §9.1 layer 5: explicit empty bound on the params side.
	for _, gv := range grantParams {
		if isEmptyBound(gv) {
			return false, ErrEmptyBoundDenies.Error()
		}
	}
	// §9.1 layer 6: grant-side null resolves before presence.
	for k, gv := range grantParams {
		if gv == nil {
			return false, fmt.Errorf("%w: %s", ErrInvalidParamsNull, k).Error()
		}
	}
	// §9.1 layer 6: operation-side null.
	for k, ov := range opParams {
		if ov == nil {
			return false, fmt.Errorf("%w: %s", ErrInvalidParamsNull, k).Error()
		}
	}
	declared := map[string]bool{}
	for k := range grantParams {
		declared[k] = true
	}
	for k := range grantBounds {
		declared[k] = true
	}
	// §9.1 layer 7: presence — params keys are always required.
	for k := range grantParams {
		if opParams == nil {
			return false, ErrParamsMissing.Error()
		}
		if _, ok := opParams[k]; !ok {
			return false, ErrParamsMissing.Error()
		}
	}
	// §9.1 layer 7: presence — a bounds key is required unless optional.
	for k, b := range grantBounds {
		if boundOptional(b) {
			continue
		}
		if opParams == nil {
			return false, ErrParamsMissing.Error()
		}
		if _, ok := opParams[k]; !ok {
			return false, ErrParamsMissing.Error()
		}
	}
	// §9.1 layer 7 (request side): key closure over the union.
	for k := range opParams {
		if !declared[k] {
			return false, fmt.Errorf("%w: %s", ErrParamsUndeclared, k).Error()
		}
	}
	// §9.1 layers 8–9: params values (unchanged §6.2 subset semantics).
	for k, gv := range grantParams {
		if ok, reason := valueSubset(opParams[k], gv); !ok {
			return false, reason
		}
	}
	// §9.1 layers 8–9: bound values.
	for k, b := range grantBounds {
		ov, present := opParams[k]
		if !present {
			continue
		}
		if ok, reason := boundSubset(ov, b); !ok {
			return false, reason
		}
	}
	return true, ""
}

// requestCardinality is the §6.5 request cardinality: an array's length, a
// scalar counts as 1.
func requestCardinality(v any) int {
	if a, ok := v.([]any); ok {
		return len(a)
	}
	return 1
}

// boundSubset reports whether an operation value satisfies a Bound (§6.5).
func boundSubset(opVal, bound any) (bool, string) {
	b, ok := bound.(map[string]any)
	if !ok {
		return false, ErrInvalidParamsBinding.Error()
	}
	// Enum family (layer 8): membership by exact equality, same rule as §6.2
	// arrays; an explicitly empty enum denies the class.
	if enumRaw, ok := b["enum"]; ok {
		gv, _ := enumRaw.([]any)
		if len(gv) == 0 {
			return false, ErrEmptyBoundDenies.Error()
		}
		elems := []any{opVal}
		if ov, ok := opVal.([]any); ok {
			elems = ov
		}
		for _, o := range elems {
			covered := false
			for _, g := range gv {
				if enumEqual(o, g) {
					covered = true
					break
				}
			}
			if !covered {
				return false, ErrNotInEnum.Error()
			}
		}
	}
	// Cardinality (layer 8).
	if mn, ok := b["min_items"].(float64); ok && float64(requestCardinality(opVal)) < mn {
		return false, ErrParamsCardinality.Error()
	}
	if mx, ok := b["max_items"].(float64); ok && float64(requestCardinality(opVal)) > mx {
		return false, ErrParamsCardinality.Error()
	}
	// Nested family.
	if nestedRaw, ok := b["nested"]; ok {
		om, ok := opVal.(map[string]any)
		if !ok {
			return false, ErrParamsExceedGrant.Error()
		}
		nm, _ := nestedRaw.(map[string]any)
		return nestedSubset(om, nm)
	}
	// Numeric family (layer 9).
	if _, ok := b["min"]; ok {
		return numericBound(opVal, b)
	}
	if _, ok := b["max"]; ok {
		return numericBound(opVal, b)
	}
	if _, ok := b["step"]; ok {
		return numericBound(opVal, b)
	}
	return true, ""
}

// numericBound applies a numeric-family Bound to a request value, returning the
// resolved reason on failure and the empty string on success.
func numericBound(opVal any, b map[string]any) (bool, string) {
	f, ok := opVal.(float64)
	if !ok {
		return false, ErrParamsExceedGrant.Error()
	}
	if mn, ok := b["min"].(float64); ok && f < mn {
		return false, ErrParamsOutOfRange.Error()
	}
	if mx, ok := b["max"].(float64); ok && f > mx {
		return false, ErrParamsOutOfRange.Error()
	}
	if st, ok := b["step"].(float64); ok && !isMultipleOf(f, st) {
		return false, ErrParamsNotMultiple.Error()
	}
	return true, ""
}

// isMultipleOf is the §6.5 step rule: v is an integer multiple of step in
// IEEE-754 binary64 (deterministic across implementations).
func isMultipleOf(v, step float64) bool {
	if step == 0 {
		return false
	}
	q := v / step
	return q == math.Trunc(q) && q*step == v
}

// nestedSubset applies a nested Bound map to an object request value with the
// same key closure and optional semantics as the top level.
func nestedSubset(op, nested map[string]any) (bool, string) {
	for k, b := range nested {
		ov, present := op[k]
		if !present {
			if boundOptional(b) {
				continue
			}
			return false, ErrParamsMissing.Error()
		}
		if ok, reason := boundSubset(ov, b); !ok {
			return false, reason
		}
	}
	for k := range op {
		if _, ok := nested[k]; !ok {
			return false, fmt.Errorf("%w: %s", ErrParamsUndeclared, k).Error()
		}
	}
	return true, ""
}

// boundWithin reports whether a child Bound is within (no wider than) a parent
// Bound, for the containment relation (§13.4.3, rev CLC-1.10).
func boundWithin(child, parent any) error {
	cb, ok := child.(map[string]any)
	if !ok {
		return ErrParamsNotNarrower
	}
	pb, ok := parent.(map[string]any)
	if !ok {
		return ErrParamsNotNarrower
	}
	// Optional must not be widened from required (parent) to optional (child).
	if !boundOptional(pb) && boundOptional(cb) {
		return ErrParamsNotNarrower
	}
	if pn, ok := pb["min"].(float64); ok {
		cn, ok := cb["min"].(float64)
		if !ok || cn < pn {
			return ErrParamsNotNarrower
		}
	}
	if px, ok := pb["max"].(float64); ok {
		cx, ok := cb["max"].(float64)
		if !ok || cx > px {
			return ErrParamsNotNarrower
		}
	}
	if ps, ok := pb["step"].(float64); ok {
		cs, ok := cb["step"].(float64)
		if !ok || !isMultipleOf(cs, ps) {
			return ErrParamsNotNarrower
		}
	}
	if pe, ok := pb["enum"].([]any); ok {
		ce, ok := cb["enum"].([]any)
		if !ok {
			return ErrParamsNotNarrower
		}
		for _, e := range ce {
			found := false
			for _, p := range pe {
				if enumEqual(e, p) {
					found = true
					break
				}
			}
			if !found {
				return ErrParamsNotNarrower
			}
		}
	}
	if pmn, ok := pb["min_items"].(float64); ok {
		cmn, ok := cb["min_items"].(float64)
		if !ok || cmn < pmn {
			return ErrParamsNotNarrower
		}
	}
	if pmx, ok := pb["max_items"].(float64); ok {
		cmx, ok := cb["max_items"].(float64)
		if !ok || cmx > pmx {
			return ErrParamsNotNarrower
		}
	}
	if pnr, ok := pb["nested"].(map[string]any); ok {
		cnr, ok := cb["nested"].(map[string]any)
		if !ok {
			return ErrParamsNotNarrower
		}
		for k, pbn := range pnr {
			cbn, ok := cnr[k]
			if !ok {
				return ErrParamsNotNarrower
			}
			if err := boundWithin(cbn, pbn); err != nil {
				return err
			}
		}
		for k := range cnr {
			if _, ok := pnr[k]; !ok {
				return ErrParamsNotNarrower
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// §6.6 BoundMeet — the intersection of param_bounds (rev CLC-1.14)
// ---------------------------------------------------------------------------

// boundFamily classifies a Bound by its value family (§6.5), or "none" for an
// empty Bound.  `optional` is orthogonal and ignored here.
func boundFamily(b any) string {
	m, ok := b.(map[string]any)
	if !ok {
		return "invalid"
	}
	if _, ok := m["nested"]; ok {
		return "nested"
	}
	for _, k := range []string{"enum", "min_items", "max_items"} {
		if _, ok := m[k]; ok {
			return "enum"
		}
	}
	for _, k := range []string{"min", "max", "step"} {
		if _, ok := m[k]; ok {
			return "numeric"
		}
	}
	return "none"
}

// canonicalEnumMembers dedupes enum members and orders them by their JCS
// rendering, so a meet result never depends on source value order or
// duplicates (P11; the array is a membership set, §6.2).
func canonicalEnumMembers(members []any) []any {
	type kv struct {
		key string
		val any
	}
	seen := map[string]bool{}
	list := make([]kv, 0, len(members))
	for _, m := range members {
		b, err := CanonicalJSON(m)
		if err != nil {
			b = []byte(fmt.Sprintf("%v", m))
		}
		k := string(b)
		if seen[k] {
			continue
		}
		seen[k] = true
		list = append(list, kv{k, m})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].key < list[j].key })
	out := make([]any, len(list))
	for i, e := range list {
		out[i] = e.val
	}
	return out
}

// cloneBound returns a shallow copy of a Bound object (never aliases a source).
func cloneBound(b any) (map[string]any, bool) {
	m, ok := b.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out, true
}

// boundDeniesClass reports whether a Bound (or a nested Bound) denies its class
// outright via an explicitly empty enum (§6.5, mirroring `{"tables":[]}` in
// §6.2).  An empty Bound `{}` does NOT deny (it only declares the key).
func boundDeniesClass(b any) bool {
	m, ok := b.(map[string]any)
	if !ok {
		return false
	}
	if e, ok := m["enum"].([]any); ok && len(e) == 0 {
		return true
	}
	if nm, ok := m["nested"].(map[string]any); ok {
		for _, nb := range nm {
			if boundDeniesClass(nb) {
				return true
			}
		}
	}
	return false
}

// boundsDenyClass reports whether any bound in a param_bounds map denies its
// class.
func boundsDenyClass(bounds map[string]any) bool {
	for _, b := range bounds {
		if boundDeniesClass(b) {
			return true
		}
	}
	return false
}

// intersectBounds merges two param_bounds maps with the §6.6 meet: keys are
// unioned (like params), and a key present on both sides meets its two Bounds.
func intersectBounds(a, b map[string]any) (map[string]any, error) {
	if len(a) == 0 && len(b) == 0 {
		return nil, nil
	}
	if len(a) == 0 {
		return cloneBoundMap(b), nil
	}
	if len(b) == 0 {
		return cloneBoundMap(a), nil
	}
	out := cloneBoundMap(a)
	for k, bv := range b {
		if av, ok := out[k]; ok {
			m, err := boundMeet(av, bv)
			if err != nil {
				return nil, err
			}
			out[k] = m
		} else {
			out[k] = bv
		}
	}
	return out, nil
}

func cloneBoundMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// boundMeet is the §6.6 meet of two Bounds for the same key.
func boundMeet(a, b any) (map[string]any, error) {
	am, aok := cloneBound(a)
	bm, bok := cloneBound(b)
	if !aok || !bok {
		return nil, ErrInvalidParamsBinding
	}
	opt := boundOptional(am) && boundOptional(bm)
	af, bf := boundFamily(am), boundFamily(bm)
	if af == "invalid" || bf == "invalid" {
		return nil, ErrInvalidParamsBinding
	}
	// Empty Bound is the identity for the value families.
	if af == "none" || bf == "none" {
		src := am
		if af == "none" {
			src = bm
		}
		res := map[string]any{}
		for k, v := range src {
			if k == "optional" {
				continue
			}
			res[k] = v
		}
		if opt {
			res["optional"] = true
		}
		return res, nil
	}
	var res map[string]any
	var err error
	switch {
	case af == "numeric" && bf == "numeric":
		res, err = numericMeet(am, bm)
	case af == "enum" && bf == "enum":
		res, err = enumMeet(am, bm)
	case af == "nested" && bf == "nested":
		res, err = nestedMeet(am, bm)
	case (af == "numeric" && bf == "enum") || (af == "enum" && bf == "numeric"):
		// rev CLC-1.15 §6.6: a cross-family numeric × enum meet has no sound
		// representation — the CLC-1.14 filtered-enum result was broader than
		// either source (it accepted array requests, e.g. [3], that the numeric
		// side fail-closes at §6.5 layer 9).  Refused in either source order
		// and regardless of whether any member falls inside the numeric range:
		// the family clash is decided before any member or range math.
		return nil, ErrInvalidParamsBinding
	case af == "nested" || bf == "nested":
		// scalar (numeric/enum) ∩ object (nested), either order: refused like
		// the numeric × enum pair — no single-family Bound can carry both the
		// scalar side's shape constraint and the object recursion (§6.6 rev
		// CLC-1.15; design-notes D12).  The family clash is decided before any
		// member, range or key-set math.
		return nil, ErrInvalidParamsBinding
	default:
		return nil, ErrInvalidParamsBinding
	}
	if err != nil {
		return nil, err
	}
	// optional is copied from the untouched source, so re-apply the conjunction.
	delete(res, "optional")
	if opt {
		res["optional"] = true
	}
	return res, nil
}

func numericMeet(a, b map[string]any) (map[string]any, error) {
	res := map[string]any{}
	// min: greatest declared minimum.
	if av, ok := a["min"].(float64); ok {
		if bv, ok := b["min"].(float64); ok {
			if av > bv {
				res["min"] = av
			} else {
				res["min"] = bv
			}
		} else {
			res["min"] = av
		}
	} else if bv, ok := b["min"].(float64); ok {
		res["min"] = bv
	}
	// max: least declared maximum.
	if av, ok := a["max"].(float64); ok {
		if bv, ok := b["max"].(float64); ok {
			if av < bv {
				res["max"] = av
			} else {
				res["max"] = bv
			}
		} else {
			res["max"] = av
		}
	} else if bv, ok := b["max"].(float64); ok {
		res["max"] = bv
	}
	// step: the coarser grid if one exactly divides the other.
	as, aok := a["step"].(float64)
	bs, bok := b["step"].(float64)
	switch {
	case aok && bok:
		if isMultipleOf(as, bs) {
			res["step"] = as
		} else if isMultipleOf(bs, as) {
			res["step"] = bs
		} else {
			return nil, ErrInvalidParamsBinding
		}
	case aok:
		res["step"] = as
	case bok:
		res["step"] = bs
	}
	if mn, ok := res["min"].(float64); ok {
		if mx, ok := res["max"].(float64); ok && mn > mx {
			return nil, ErrNoOverlap
		}
	}
	return res, nil
}

func enumMeet(a, b map[string]any) (map[string]any, error) {
	res := map[string]any{}
	ae, aok := a["enum"].([]any)
	be, bok := b["enum"].([]any)
	switch {
	case aok && bok:
		inter := []any{}
		for _, x := range ae {
			for _, y := range be {
				if enumEqual(x, y) {
					inter = append(inter, x)
					break
				}
			}
		}
		if len(inter) == 0 {
			return nil, ErrNoOverlap
		}
		res["enum"] = canonicalEnumMembers(inter)
	case aok:
		res["enum"] = ae
	case bok:
		res["enum"] = be
	}
	if v, ok := maxOf(a["min_items"], b["min_items"]); ok {
		res["min_items"] = v
	}
	if v, ok := minOf(a["max_items"], b["max_items"]); ok {
		res["max_items"] = v
	}
	if mn, ok := res["min_items"].(float64); ok {
		if mx, ok := res["max_items"].(float64); ok && mn > mx {
			return nil, ErrNoOverlap
		}
	}
	return res, nil
}

func nestedMeet(a, b map[string]any) (map[string]any, error) {
	an, _ := a["nested"].(map[string]any)
	bn, _ := b["nested"].(map[string]any)
	if len(an) != len(bn) {
		return nil, ErrNoOverlap
	}
	res := map[string]any{}
	for k, av := range an {
		bv, ok := bn[k]
		if !ok {
			return nil, ErrNoOverlap
		}
		m, err := boundMeet(av, bv)
		if err != nil {
			return nil, err
		}
		res[k] = m
	}
	return map[string]any{"nested": res}, nil
}

// maxOf / minOf return the greater / lesser of two declared float64 bounds,
// and ok=false when neither is declared.
func maxOf(a, b any) (any, bool) {
	av, aok := a.(float64)
	bv, bok := b.(float64)
	switch {
	case aok && bok:
		if av > bv {
			return av, true
		}
		return bv, true
	case aok:
		return av, true
	case bok:
		return bv, true
	}
	return nil, false
}

func minOf(a, b any) (any, bool) {
	av, aok := a.(float64)
	bv, bok := b.(float64)
	switch {
	case aok && bok:
		if av < bv {
			return av, true
		}
		return bv, true
	case aok:
		return av, true
	case bok:
		return bv, true
	}
	return nil, false
}

// MaterializeDefaults applies the §6.5 scheme-default rule: for every key the
// operation omits that the grant declares and the scheme gives a default for,
// the default is injected before evaluation (precedence explicit > default >
// absent).  A default never adds a key the grant does not declare.
func MaterializeDefaults(grant Grant, op Operation, defaults map[string]any) Operation {
	if len(defaults) == 0 {
		return op
	}
	declared := grantDeclaredKeys(grant)
	merged := map[string]any{}
	for k, v := range op.Params {
		merged[k] = v
	}
	injected := false
	for k, dv := range defaults {
		if !declared[k] {
			continue
		}
		if _, ok := merged[k]; !ok {
			merged[k] = dv
			injected = true
		}
	}
	if !injected {
		return op
	}
	return Operation{ID: op.ID, Params: merged}
}
