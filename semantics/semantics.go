// Package semantics implements the CLC-v1 capability language core
// authorization semantics.  It provides deterministic, fail-closed
// entailment, intersection, and decision functions.
package semantics

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Grant represents a principal's authorization of a capability.
type Grant struct {
	ID          string         `json:"id"`
	Params      map[string]any `json:"params,omitempty"`
	Constraints []string       `json:"constraints,omitempty"`
}

// Operation represents a concrete action request.
type Operation struct {
	ID     string         `json:"id"`
	Params map[string]any `json:"params,omitempty"`
}

// Decision is the output of the authorization function.
type Decision struct {
	Verdict string `json:"verdict"` // "allow" or "deny"
	Reason  string `json:"reason,omitempty"`
}

// MatchResult captures the result of an entailment check.
type MatchResult struct {
	Entails bool
	Reason  string
}

var (
	ErrUnsupportedWildcard = errors.New("unsupported_wildcard")
	ErrInvalidCapabilityID = errors.New("invalid_capability_id")
	ErrMissingCapabilityID = errors.New("missing_capability_id")
	ErrInvalidParamsNull   = errors.New("invalid_params_null")
	ErrParamsMissing       = errors.New("params_missing")
	ErrParamsUndeclared    = errors.New("undeclared_param")
	ErrCapabilityNotAuth   = errors.New("capability_not_authorized")
	ErrUnknownConstraint   = errors.New("unknown_constraint")
	ErrDifferentNamespace  = errors.New("different_namespace")
	ErrLiteralMismatch     = errors.New("literal_mismatch")
	ErrWildcardNoTrailing  = errors.New("wildcard_requires_trailing_segment")
	ErrParamsExceedGrant   = errors.New("params_exceed_grant")
	ErrEmptyBoundDenies    = errors.New("empty_bound_denies_class")
	ErrNotInEnum           = errors.New("not_in_enum")
	ErrNoOverlap           = errors.New("no_overlap")
	ErrAbsentSource        = errors.New("absent_source")
	ErrInvalidParamsDupKey = errors.New("invalid_params_duplicate_key")
	ErrInvalidParamsNumber = errors.New("invalid_params_number")
	ErrInvalidParamsSize   = errors.New("invalid_params_size")
	ErrUnsupportedLangRev  = errors.New("unsupported_language_revision")
)

// ValidateCapabilityID checks whether an ID conforms to CLC-v1 §2 grammar.
// v1 allows: literal segments and trailing * as a complete segment.
func ValidateCapabilityID(id string) error {
	if id == "" {
		return ErrMissingCapabilityID
	}
	// Check for forbidden shapes
	if id == "*" {
		return ErrUnsupportedWildcard
	}
	if strings.Contains(id, "**") {
		return ErrUnsupportedWildcard
	}
	if strings.Contains(id, "{") || strings.Contains(id, "}") {
		return ErrUnsupportedWildcard
	}
	if strings.Contains(id, "[") || strings.Contains(id, "]") {
		return ErrUnsupportedWildcard
	}
	// Check for partial segment wildcard
	parts := strings.Split(id, ":")
	for i, p := range parts {
		if strings.Contains(p, "*") {
			if p != "*" {
				return ErrUnsupportedWildcard
			}
			if i != len(parts)-1 {
				return ErrUnsupportedWildcard
			}
		}
	}
	// Must have at least scheme:action
	if len(parts) < 2 {
		return ErrInvalidCapabilityID
	}
	return nil
}

// ValidateGrantParams checks for null values in params (CLC-v1 §5.2).
func ValidateGrantParams(params map[string]any) error {
	for k, v := range params {
		if v == nil {
			return fmt.Errorf("%w: %s", ErrInvalidParamsNull, k)
		}
	}
	return nil
}

// ValidateOperationParams checks for null values in operation params.
func ValidateOperationParams(params map[string]any) error {
	for k, v := range params {
		if v == nil {
			return fmt.Errorf("%w: %s", ErrInvalidParamsNull, k)
		}
	}
	return nil
}

// CLCRevision is the language revision this implementation declares and
// evaluates.  Compatible reading (§12.1): same major, minor ≤ ours.
const CLCRevision = "CLC-1.1"

const (
	// maxParamsSerializedBytes bounds the JCS-serialized params size
	// (§6.2 step 4).
	maxParamsSerializedBytes = 512
	// maxParamsNesting bounds params nesting depth (§6.2 step 4).
	maxParamsNesting = 32
)

// RevisionCompatible reports whether an input declaring the given CLC
// revision may be evaluated by this implementation (§12.1).  A mismatch is
// resolved before any §9.3 layer and fails closed with
// unsupported_language_revision — never a silent downgrade.
func RevisionCompatible(inputRevision string) bool {
	iMaj, iMin, ok := parseRevision(inputRevision)
	if !ok {
		return false
	}
	maj, min, _ := parseRevision(CLCRevision)
	return iMaj == maj && iMin <= min
}

func parseRevision(rev string) (major, minor int, ok bool) {
	rest, found := strings.CutPrefix(rev, "CLC-")
	if !found {
		return 0, 0, false
	}
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || maj < 0 || min < 0 {
		return 0, 0, false
	}
	return maj, min, true
}

// ValidateRawParams validates the raw JSON text of an operation's params
// object at the input boundary (§6.2, §9.3 layer 2), before any layer runs.
// Unlike a decoded map, the raw text preserves duplicate keys, number
// literals, nesting depth and serialized size — none of which survive a
// map-based decode (maps drop duplicate keys, and JSON cannot carry
// non-finite numbers).  Rejections follow §6.2 order: size/depth, then
// duplicate keys, then number shape.  Malformed input and a non-object
// params value fall into invalid_params_number.
func ValidateRawParams(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return ErrInvalidParamsNumber
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var buf bytes.Buffer
	var dupErr, numErr error
	if err := walkParamsValue(dec, &buf, 1, &dupErr, &numErr); err != nil {
		if errors.Is(err, ErrInvalidParamsSize) {
			return err
		}
		return ErrInvalidParamsNumber
	}
	// Trailing tokens after the params object → malformed.
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalidParamsNumber
	}
	if buf.Len() > maxParamsSerializedBytes {
		return ErrInvalidParamsSize
	}
	if dupErr != nil {
		return dupErr
	}
	if numErr != nil {
		return numErr
	}
	return nil
}

// walkParamsValue re-serializes params into a compact canonical buffer
// (RFC 8785 style, for the §6.2 size check) while detecting duplicate keys,
// invalid number shapes and over-deep nesting.  depth counts open containers,
// the params object being 1.
func walkParamsValue(dec *json.Decoder, buf *bytes.Buffer, depth int, dupErr, numErr *error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			if depth > maxParamsNesting {
				return ErrInvalidParamsSize
			}
			buf.WriteByte('{')
			keys := make(map[string]bool)
			first := true
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := ktok.(string)
				if !ok {
					return fmt.Errorf("params object key must be a string")
				}
				if keys[key] && *dupErr == nil {
					*dupErr = fmt.Errorf("%w: %q", ErrInvalidParamsDupKey, key)
				}
				keys[key] = true
				if !first {
					buf.WriteByte(',')
				}
				first = false
				kb, err := json.Marshal(key)
				if err != nil {
					return err
				}
				buf.Write(kb)
				buf.WriteByte(':')
				if err := walkParamsValue(dec, buf, depth+1, dupErr, numErr); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := end.(json.Delim); !ok || d != '}' {
				return fmt.Errorf("expected params object close")
			}
			buf.WriteByte('}')
			return nil
		case '[':
			if depth > maxParamsNesting {
				return ErrInvalidParamsSize
			}
			buf.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					buf.WriteByte(',')
				}
				first = false
				if err := walkParamsValue(dec, buf, depth+1, dupErr, numErr); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := end.(json.Delim); !ok || d != ']' {
				return fmt.Errorf("expected params array close")
			}
			buf.WriteByte(']')
			return nil
		default:
			return fmt.Errorf("unexpected params delimiter")
		}
	case json.Number:
		if err := checkParamsNumber(string(t)); err != nil {
			if *numErr == nil {
				*numErr = fmt.Errorf("%w: %s", ErrInvalidParamsNumber, string(t))
			}
		}
		buf.WriteString(string(t))
		return nil
	case float64:
		if !isFinite(t) {
			if *numErr == nil {
				*numErr = fmt.Errorf("%w: %v", ErrInvalidParamsNumber, t)
			}
		}
		kb, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(kb)
		return nil
	case string:
		kb, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(kb)
		return nil
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case nil:
		buf.WriteString("null")
		return nil
	default:
		return fmt.Errorf("unexpected params token")
	}
}

var numericLiteralRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// checkParamsNumber rejects non-finite or over-precision numeric params
// (§6.2 step 3).
func checkParamsNumber(lit string) error {
	if !numericLiteralRE.MatchString(lit) {
		return ErrInvalidParamsNumber
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || !isFinite(f) {
		return ErrInvalidParamsNumber
	}
	if significantDigits(lit) > 17 {
		return ErrInvalidParamsNumber
	}
	return nil
}

// isFinite reports whether a float64 is neither NaN nor infinite.
func isFinite(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

func significantDigits(lit string) int {
	s := lit
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "-")
	s = strings.Replace(s, ".", "", 1)
	s = strings.TrimLeft(s, "0")
	s = strings.TrimRight(s, "0")
	return len(s)
}

// matchID checks if grant ID covers operation ID per CLC-v1 §5.1 + §9.3.
// Layer 3 (namespace = scheme + action Class) is evaluated first, then
// Layer 4 (path coverage). Trailing * matches one or more segments.
func matchID(grantID, opID string) (bool, string) {
	gParts := strings.Split(grantID, ":")
	oParts := strings.Split(opID, ":")

	// §9.3 layer 3: namespace (scheme + action Class)
	if namespaceOf(grantID) != namespaceOf(opID) {
		return false, ErrDifferentNamespace.Error()
	}

	// §9.3 layer 4: path coverage within the same namespace
	if len(gParts) != len(oParts) {
		// Check if last part is wildcard
		if gParts[len(gParts)-1] == "*" {
			// Wildcard needs at least one trailing segment
			if len(oParts) <= len(gParts)-1 {
				return false, ErrWildcardNoTrailing.Error()
			}
			// Compare prefix parts
			for i := 0; i < len(gParts)-1; i++ {
				if gParts[i] != oParts[i] {
					return false, ErrLiteralMismatch.Error()
				}
			}
			return true, ""
		}
		// Exact grant does not broaden to a longer path
		return false, ErrLiteralMismatch.Error()
	}

	// Same length: compare segment by segment
	for i := range gParts {
		if gParts[i] == "*" {
			// Wildcard in last position matches any value in that position
			// (but requires at least one trailing segment, handled by the
			// length check above; mid-ID wildcards are rejected earlier by
			// ValidateCapabilityID)
			if i == len(gParts)-1 {
				return true, ""
			}
			return false, ErrLiteralMismatch.Error()
		}
		if gParts[i] != oParts[i] {
			return false, ErrLiteralMismatch.Error()
		}
	}
	return true, ""
}

// namespaceOf returns scheme:action_class (the first two ":-delimited
// segments), per CLC-v1 §9.3 layer 3.
func namespaceOf(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) < 2 {
		return id
	}
	return parts[0] + ":" + parts[1]
}

// paramsSubset checks if operation params are a subset of grant params
// per CLC-v1 §5.2. When several conditions fail at once, the resolved
// reason follows §9.3 layers 5–9 (empty bound, null, presence, enum,
// bound). Layer 7 key closure: grant keys must be present in the op
// (params_missing) before op keys must be declared by the grant
// (undeclared_param).
func paramsSubset(opParams, grantParams map[string]any) (bool, string) {
	if grantParams == nil {
		return true, ""
	}
	// §9.3 layer 5: explicit empty bound ([] or {}) on the grant side
	for _, gv := range grantParams {
		if isEmptyBound(gv) {
			return false, ErrEmptyBoundDenies.Error()
		}
	}
	// §9.3 layer 6: null values.  This runs BEFORE layer 7 presence, so a grant
	// that carries a null reports invalid_params_null even when the operation
	// omits the params object entirely (§6.3 layer-6 note).
	for k, gv := range grantParams {
		if gv == nil {
			return false, fmt.Errorf("%w: %s", ErrInvalidParamsNull, k).Error()
		}
	}
	// §9.3 layer 7: presence — the operation must carry a params object.
	if opParams == nil {
		return false, ErrParamsMissing.Error()
	}
	for k, ov := range opParams {
		if ov == nil {
			return false, fmt.Errorf("%w: %s", ErrInvalidParamsNull, k).Error()
		}
	}
	// §9.3 layer 7: presence (all grant keys must be present in op)
	for k := range grantParams {
		if _, ok := opParams[k]; !ok {
			return false, ErrParamsMissing.Error()
		}
	}
	// §9.3 layer 7 (request side): key closure — every op key must be
	// declared by the grant; the missing-key check above resolves first.
	for k := range opParams {
		if _, ok := grantParams[k]; !ok {
			return false, fmt.Errorf("%w: %s", ErrParamsUndeclared, k).Error()
		}
	}
	// §9.3 layers 8–9: per-key value checks (enum membership, bounds)
	for k, gv := range grantParams {
		if ok, reason := valueSubset(opParams[k], gv); !ok {
			return false, reason
		}
	}
	return true, ""
}

// isEmptyBound reports whether a param value is an explicit empty [] or {}
// (CLC-v1 §9.3 layer 5: deny-when-declared).
func isEmptyBound(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// hasEmptyBound reports whether any param value in the map is an explicit
// empty bound (used by Intersect's deny-when-declared scan).
func hasEmptyBound(params map[string]any) bool {
	for _, v := range params {
		if isEmptyBound(v) {
			return true
		}
	}
	return false
}

func valueSubset(opVal, grantVal any) (bool, string) {
	if opVal == nil {
		return false, ErrInvalidParamsNull.Error()
	}
	if grantVal == nil {
		return false, ErrEmptyBoundDenies.Error()
	}

	switch gv := grantVal.(type) {
	case float64:
		ov, ok := opVal.(float64)
		if !ok {
			return false, ErrParamsExceedGrant.Error()
		}
		if ov > gv {
			return false, ErrParamsExceedGrant.Error()
		}
		return true, ""
	case string:
		ov, ok := opVal.(string)
		if !ok || ov != gv {
			return false, ErrParamsExceedGrant.Error()
		}
		return true, ""
	case bool:
		ov, ok := opVal.(bool)
		if !ok || ov != gv {
			return false, ErrParamsExceedGrant.Error()
		}
		return true, ""
	case []any:
		// v1.1 enum semantics: an array-valued grant parameter is the
		// set of allowed values. The request may supply a scalar (must
		// equal a member) or an array (every element must equal a
		// member). Members compare by exact equality; a number inside
		// the set is an exact value, not a bound. An explicitly empty
		// grant set denies the class.
		if len(gv) == 0 {
			return false, ErrEmptyBoundDenies.Error()
		}
		var elems []any
		if ov, ok := opVal.([]any); ok {
			elems = ov
		} else {
			elems = []any{opVal}
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
		return true, ""
	case map[string]any:
		ov, ok := opVal.(map[string]any)
		if !ok {
			return false, ErrParamsExceedGrant.Error()
		}
		for k, gvv := range gv {
			ovv, ok := ov[k]
			if !ok {
				return false, ErrParamsMissing.Error()
			}
			if ok, reason := valueSubset(ovv, gvv); !ok {
				return false, reason
			}
		}
		return true, ""
	default:
		// Exact equality
		if fmt.Sprintf("%v", opVal) != fmt.Sprintf("%v", grantVal) {
			return false, ErrParamsExceedGrant.Error()
		}
		return true, ""
	}
}

// enumEqual reports exact JSON-value equality, used for set membership in
// the v1.1 array (enum) rule. Numbers compare as exact values, not bounds.
func enumEqual(a, b any) bool {
	ca, errA := CanonicalJSON(a)
	cb, errB := CanonicalJSON(b)
	if errA != nil || errB != nil {
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
	return string(ca) == string(cb)
}

// Entails checks if a grant covers an operation per CLC-v1 §5.
func Entails(grant Grant, op Operation) MatchResult {
	// Validate IDs
	if err := ValidateCapabilityID(grant.ID); err != nil {
		return MatchResult{Entails: false, Reason: err.Error()}
	}
	if err := ValidateCapabilityID(op.ID); err != nil {
		return MatchResult{Entails: false, Reason: err.Error()}
	}

	// §5.3 step 1: scheme check
	gScheme := grant.ID[:strings.Index(grant.ID, ":")]
	oScheme := op.ID[:strings.Index(op.ID, ":")]
	if gScheme != oScheme {
		return MatchResult{Entails: false, Reason: ErrDifferentNamespace.Error()}
	}

	// §5.3 step 2: id coverage
	if ok, reason := matchID(grant.ID, op.ID); !ok {
		return MatchResult{Entails: false, Reason: reason}
	}

	// §5.3 step 3: grant params absent → true (unconstrained)
	if grant.Params == nil {
		return MatchResult{Entails: true}
	}

	// §9.3 layer 6 (null) runs BEFORE layer 7 (presence): a grant that carries
	// a null reports invalid_params_null even when the operation omits params
	// entirely.  §6.3 layer-6 note.
	if err := ValidateGrantParams(grant.Params); err != nil {
		return MatchResult{Entails: false, Reason: err.Error()}
	}

	// §5.3 step 4: op params absent → false (bounded grant, fail-closed)
	if op.Params == nil {
		return MatchResult{Entails: false, Reason: ErrParamsMissing.Error()}
	}

	if err := ValidateOperationParams(op.Params); err != nil {
		return MatchResult{Entails: false, Reason: err.Error()}
	}

	// §5.3 step 5: params subset
	if ok, reason := paramsSubset(op.Params, grant.Params); !ok {
		return MatchResult{Entails: false, Reason: reason}
	}

	return MatchResult{Entails: true}
}

// Intersect combines multiple grants per CLC-v1 §6.
// Returns the effective grant or an error.
func Intersect(grants ...Grant) (Grant, error) {
	if len(grants) == 0 {
		return Grant{}, ErrAbsentSource
	}

	// §9.3 layer 5: deny-when-declared — any source with an explicitly
	// empty bound ([] or {}) denies the class before any member math.
	for _, g := range grants {
		if g.Params != nil && hasEmptyBound(g.Params) {
			return Grant{}, ErrEmptyBoundDenies
		}
	}

	// Start with the first grant
	result := grants[0]

	// Validate params
	if result.Params != nil {
		if err := ValidateGrantParams(result.Params); err != nil {
			return Grant{}, err
		}
	}

	// Merge with remaining grants
	for _, g := range grants[1:] {
		if g.Params != nil {
			if err := ValidateGrantParams(g.Params); err != nil {
				return Grant{}, err
			}
		}

		// Check ID compatibility (§7 rule 2: the result must be covered by
		// every source, so the *narrower* identifier wins).
		//
		// The comparison is deliberately params-free: `Entails` is the
		// authorization relation and fails closed when a bounded grant meets an
		// operation with no params (§6.3 step 4), which would make two grants
		// carrying a present-but-empty `params` object look disjoint.
		if result.ID != g.ID {
			switch {
			case Entails(Grant{ID: result.ID}, Operation{ID: g.ID}).Entails:
				// g is the narrower identifier
				result.ID = g.ID
			case !Entails(Grant{ID: g.ID}, Operation{ID: result.ID}).Entails:
				return Grant{}, ErrNoOverlap
				// otherwise result stays the narrower identifier
			}
		}

		// Intersect params
		if result.Params != nil && g.Params != nil {
			intersected := make(map[string]any)
			for k, rv := range result.Params {
				if gv, ok := g.Params[k]; ok {
					if v, err := intersectValue(rv, gv); err != nil {
						return Grant{}, err
					} else {
						intersected[k] = v
					}
				} else {
					// Key only in result, keep it
					intersected[k] = rv
				}
			}
			// Keys only in g
			for k, gv := range g.Params {
				if _, ok := result.Params[k]; !ok {
					intersected[k] = gv
				}
			}
			result.Params = intersected
		} else if g.Params == nil {
			// g is unconstrained, keep result params
		} else {
			// result is unconstrained, adopt g params
			result.Params = g.Params
		}

		// Merge constraints (§7 rule 3): constraints are conjunctive, so the
		// merge is a set *union* — every constraint of every source stays in
		// force, and for the same constraint type the tightest one binds by
		// construction (CheckConstraint denies on any violation).
		result.Constraints = mergeConstraints(result.Constraints, g.Constraints)
	}

	return result, nil
}

func intersectValue(a, b any) (any, error) {
	switch av := a.(type) {
	case float64:
		bv, ok := b.(float64)
		if !ok {
			return nil, ErrNoOverlap
		}
		if av < bv {
			return av, nil
		}
		return bv, nil
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return nil, ErrNoOverlap
		}
		var result []any
		for _, ai := range av {
			for _, bi := range bv {
				if fmt.Sprintf("%v", ai) == fmt.Sprintf("%v", bi) {
					result = append(result, ai)
					break
				}
			}
		}
		if len(result) == 0 {
			return nil, ErrNoOverlap
		}
		return result, nil
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return nil, ErrNoOverlap
		}
		result := make(map[string]any)
		for k, avv := range av {
			if bvv, ok := bv[k]; ok {
				if v, err := intersectValue(avv, bvv); err != nil {
					return nil, err
				} else {
					result[k] = v
				}
			}
		}
		if len(result) == 0 {
			return nil, ErrNoOverlap
		}
		return result, nil
	default:
		if fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b) {
			return a, nil
		}
		return nil, ErrNoOverlap
	}
}

func mergeConstraints(a, b []string) []string {
	set := make(map[string]bool)
	for _, c := range a {
		set[c] = true
	}
	for _, c := range b {
		set[c] = true
	}
	var result []string
	for c := range set {
		result = append(result, c)
	}
	return result
}

// Authorize evaluates the decision function per CLC-v1 §8.
func Authorize(effectiveGrant Grant, op Operation) Decision {
	// Absent/empty grant: no capability to check → fail-closed (§9 layer 10).
	if effectiveGrant.ID == "" {
		return Decision{Verdict: "deny", Reason: ErrCapabilityNotAuth.Error()}
	}
	// Step 1: Validate operation
	if op.ID == "" {
		return Decision{Verdict: "deny", Reason: ErrMissingCapabilityID.Error()}
	}
	if err := ValidateCapabilityID(op.ID); err != nil {
		// Propagate the specific layer-1 code (missing_capability_id /
		// unsupported_wildcard / invalid_capability_id) instead of collapsing
		// every malformed operation id into the generic code.
		return Decision{Verdict: "deny", Reason: err.Error()}
	}

	// Validate operation params for null
	if op.Params != nil {
		if err := ValidateOperationParams(op.Params); err != nil {
			return Decision{Verdict: "deny", Reason: err.Error()}
		}
	}

	// Step 2: Check entailment
	result := Entails(effectiveGrant, op)
	if !result.Entails {
		if isParamsLevelReason(result.Reason) {
			return Decision{Verdict: "deny", Reason: result.Reason}
		}
		return Decision{Verdict: "deny", Reason: ErrCapabilityNotAuth.Error()}
	}

	// Step 3: Evaluate constraints
	for _, c := range effectiveGrant.Constraints {
		if err := ValidateConstraint(c); err != nil {
			return Decision{Verdict: "deny", Reason: ErrUnknownConstraint.Error()}
		}
		// Known constraint - check if violated
		if err := CheckConstraint(c, op); err != nil {
			return Decision{Verdict: "deny", Reason: err.Error()}
		}
	}

	return Decision{Verdict: "allow"}
}

// knownConstraintTypes is the set of constraint types known to this v1 implementation.
// Unknown types are rejected (fail-closed per CLC-v1 §7).
var knownConstraintTypes = map[string]bool{
	"max_rows":     true,
	"time:window":  true,
	"network:cidr": true,
}

// ValidateConstraint checks if a constraint is known (CLC-v1 §7).
func ValidateConstraint(c string) error {
	parts := strings.Split(c, ":")
	if len(parts) < 2 {
		return ErrUnknownConstraint
	}
	// Check if constraint type is known
	// Constraint format: scheme:type or scheme:type:params
	// We check the type part (index 1)
	if len(parts) >= 2 {
		constraintType := parts[1]
		if !knownConstraintTypes[constraintType] {
			return ErrUnknownConstraint
		}
	}
	return nil
}

// CheckConstraint evaluates a constraint against an operation.
func CheckConstraint(c string, op Operation) error {
	// Parse constraint type
	parts := strings.Split(c, ":")
	if len(parts) < 3 {
		return nil // No params to check
	}
	constraintType := parts[1]

	switch constraintType {
	case "max_rows":
		if len(parts) >= 3 {
			var maxVal float64
			if _, err := fmt.Sscanf(parts[2], "%f", &maxVal); err == nil {
				if rows, ok := op.Params["max_rows"].(float64); ok {
					if rows > maxVal {
						return fmt.Errorf("max_rows:violated")
					}
				}
			}
		}
	}
	return nil
}

// CanonicalJSON returns RFC 8785 (JCS) canonical JSON.
// This is a simplified implementation; production use should use
// a proper JCS library.
func CanonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// isParamsLevelReason reports whether an entailment failure is a
// params-level reason (propagated by Authorize) rather than an
// ID-level reason (collapsed to capability_not_authorized per
// CLC-v1 §9 step 3).
func isParamsLevelReason(reason string) bool {
	prefixes := []string{
		ErrParamsMissing.Error(),
		ErrParamsUndeclared.Error(),
		ErrParamsExceedGrant.Error(),
		ErrEmptyBoundDenies.Error(),
		ErrNotInEnum.Error(),
		ErrInvalidParamsNull.Error(),
		ErrInvalidParamsDupKey.Error(),
		ErrInvalidParamsNumber.Error(),
		ErrInvalidParamsSize.Error(),
		ErrUnsupportedLangRev.Error(),
	}
	for _, p := range prefixes {
		if strings.HasPrefix(reason, p) {
			return true
		}
	}
	return false
}

// ValidateIDRegex is used for syntax validation in vectors.
var ValidateIDRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*/[a-zA-Z][a-zA-Z0-9-]*-v[0-9]+:[a-zA-Z][a-zA-Z0-9_:.-]*$`)
