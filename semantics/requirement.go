// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// CLC-REQUIREMENT-v1 — the relying party's evidence sufficiency bar.
//
// The evidence side can evaluate constraints (freshness, quorum, exclusion,
// consumption) but it must not decide *how much* evidence is enough: a
// presenter that picks its own bar is the confused-deputy failure of evidence
// systems (AEC §4, AEG §3: "the chain document cannot supply or weaken it").
// This object is that bar, supplied by relying-party configuration:
//
//	{
//	  "@version":    "CLC-REQUIREMENT-v1",
//	  "requirement_id": "wire-release-evidence@7",
//	  "purpose":     "pre-execution evidence check",
//	  "expression":  "human-authorization AND policy-permit",
//	  "constraints": [ { "role": "human-authorization",
//	                     "constraint": "varwof/evidence-v1:quorum:distinct:2" } ]
//	}
//
// Three rules are taken from AEC rather than invented:
//
//   - the expression grammar is bounded and must NOT be a general-purpose
//     evaluator (§8).  AND/OR have equal binding strength and evaluate strictly
//     left to right; parentheses are the only precedence.  An unknown
//     identifier evaluates to false.
//   - the object is closed: unknown members are rejected, not ignored
//     (AEB §5.6: "A conforming implementation MUST reject unknown terms").
//   - the requirement profile digest is the JCS digest of the complete object,
//     so a record can bind exactly which bar was applied.

package semantics

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RequirementVersion is the only @version this revision accepts.
const RequirementVersion = "CLC-REQUIREMENT-v1"

const (
	maxRequirementExpressionBytes = 512
	maxRequirementNodes           = 64
	maxRequirementDepth           = 8
)

// RequirementConstraint binds one evidence-side constraint to the evidence role
// it is evaluated over.
type RequirementConstraint struct {
	Role       string `json:"role"`
	Constraint string `json:"constraint"`
}

// Requirement is the relying party's sufficiency bar for one evidence check.
type Requirement struct {
	Version     string                  `json:"@version"`
	ID          string                  `json:"requirement_id"`
	Purpose     string                  `json:"purpose,omitempty"`
	Expression  string                  `json:"expression"`
	Constraints []RequirementConstraint `json:"constraints,omitempty"`
}

var (
	// ErrRequirementShape means the object is malformed, carries unknown
	// members, or its expression exceeds the bounded parser's limits.
	ErrRequirementShape = errors.New("requirement_shape")
	// ErrRequirementVersion means @version is not CLC-REQUIREMENT-v1.
	ErrRequirementVersion = errors.New("requirement_version")
	// ErrRequirementExpression means the expression does not parse under the
	// bounded grammar.
	ErrRequirementExpression = errors.New("requirement_expression")
)

// ParseRequirement decodes a requirement as a closed object: a member this
// revision does not define is an error, never silently dropped.  (AEC §4's
// requirement is likewise a closed object.)
func ParseRequirement(raw []byte) (Requirement, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req Requirement
	if err := dec.Decode(&req); err != nil {
		return Requirement{}, fmt.Errorf("%w: %v", ErrRequirementShape, err)
	}
	if err := req.Validate(); err != nil {
		return Requirement{}, err
	}
	return req, nil
}

// Validate checks the version, the identifiers, every constraint's value
// grammar, and that the expression parses within the bounded grammar.
func (r Requirement) Validate() error {
	if r.Version != RequirementVersion {
		return fmt.Errorf("%w: %q", ErrRequirementVersion, r.Version)
	}
	if r.ID == "" {
		return fmt.Errorf("%w: requirement_id required", ErrRequirementShape)
	}
	if len(r.Expression) > maxRequirementExpressionBytes {
		return fmt.Errorf("%w: expression longer than %d bytes", ErrRequirementShape, maxRequirementExpressionBytes)
	}
	if _, err := parseRequirementExpression(r.Expression); err != nil {
		return err
	}
	seen := make(map[string]bool, len(r.Constraints))
	for _, c := range r.Constraints {
		if c.Role == "" {
			return fmt.Errorf("%w: constraint without a role", ErrRequirementShape)
		}
		if err := ValidateEvidenceConstraint(c.Constraint); err != nil {
			return err
		}
		key := c.Role + "\x00" + c.Constraint
		if seen[key] {
			return fmt.Errorf("%w: duplicate constraint for role %q", ErrRequirementShape, c.Role)
		}
		seen[key] = true
	}
	return nil
}

// Digest is the requirement profile digest: the JCS digest of the complete
// object, so two parties agree on which bar was applied (AEC §4).
func (r Requirement) Digest() (Digest, error) {
	if err := r.Validate(); err != nil {
		return Digest{}, err
	}
	return DigestOf(r)
}

// Roles returns the sorted distinct role identifiers the expression names.
func (r Requirement) Roles() ([]string, error) {
	expr, err := parseRequirementExpression(r.Expression)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	expr.roles(set)
	out := make([]string, 0, len(set))
	for role := range set {
		out = append(out, role)
	}
	sort.Strings(out)
	return out, nil
}

// RequirementResult is the outcome of evaluating a requirement over facts.
type RequirementResult struct {
	RequirementID string               `json:"requirement_id"`
	Digest        Digest               `json:"digest"`
	Verdict       EvidenceVerdict      `json:"verdict"`
	Expression    bool                 `json:"expression"`
	MissingRoles  []string             `json:"missing_roles,omitempty"`
	Constraints   []EvidenceEvaluation `json:"constraints,omitempty"`
}

// EvaluateRequirement decides whether the presented facts fill the relying
// party's bar.  The requirement must come from relying-party configuration: this
// function takes it as an argument and never reads it from the evidence.
//
// Precedence is violated > unknown > satisfied, so no failure degrades toward
// admission: a violated constraint or a false expression is a definite refusal,
// and a constraint this revision cannot decide (consumption, an unsupplied
// boundary identity) leaves the outcome unknown for the consumer to resolve.
func EvaluateRequirement(req Requirement, facts []EvidenceFact, ctx EvidenceContext) (RequirementResult, error) {
	if err := req.Validate(); err != nil {
		return RequirementResult{}, err
	}
	digest, err := req.Digest()
	if err != nil {
		return RequirementResult{}, err
	}
	out := RequirementResult{RequirementID: req.ID, Digest: digest}

	expr, err := parseRequirementExpression(req.Expression)
	if err != nil {
		return RequirementResult{}, err
	}
	present := func(role string) bool {
		for _, f := range EvidenceFactsOfRole(facts, role) {
			if f.Verified {
				return true
			}
		}
		return false
	}
	out.Expression = expr.eval(present)
	if !out.Expression {
		roles, _ := req.Roles()
		for _, role := range roles {
			if !present(role) {
				out.MissingRoles = append(out.MissingRoles, role)
			}
		}
	}

	unknown := false
	violated := false
	for _, c := range req.Constraints {
		evaluation, err := EvaluateEvidenceConstraint(c.Constraint, EvidenceFactsOfRole(facts, c.Role), ctx)
		if err != nil {
			return RequirementResult{}, err
		}
		out.Constraints = append(out.Constraints, evaluation)
		switch evaluation.Verdict {
		case EvidenceViolated:
			violated = true
		case EvidenceUnknown:
			unknown = true
		}
	}

	switch {
	case violated || !out.Expression:
		out.Verdict = EvidenceViolated
	case unknown:
		out.Verdict = EvidenceUnknown
	default:
		out.Verdict = EvidenceSatisfied
	}
	return out, nil
}

// Satisfied is the convenience predicate: only an explicit satisfied verdict
// counts, so "unknown" can never be read as "yes".
func (r RequirementResult) Satisfied() bool {
	return r.Verdict == EvidenceSatisfied
}

// SatisfactionVerdict is the verdict of §10's exported report.  The evaluation
// itself is three-valued; this report is binary.
type SatisfactionVerdict string

const (
	// SatisfactionSatisfied means every required role was filled and bound and
	// no constraint failed.
	SatisfactionSatisfied SatisfactionVerdict = "SATISFIED"
	// SatisfactionUnsatisfied means the requirement was not met.  It covers
	// both an internal `violated` and an internal `unknown`: §10 requires an
	// undecidable constraint to collapse to UNSATISFIED with a stable reason,
	// never to SATISFIED.
	SatisfactionUnsatisfied SatisfactionVerdict = "UNSATISFIED"
)

// Report reason codes that are not already carried by a constraint evaluation.
const (
	// SatisfactionReasonExpressionFalse means the requirement's expression was
	// not filled by eligible facts.
	SatisfactionReasonExpressionFalse = "requirement:expression_false"
	// SatisfactionReasonUnsatisfied is the fallback when no more specific
	// reason is available; it keeps the report deterministic.
	SatisfactionReasonUnsatisfied = "requirement:unsatisfied"
)

// Satisfaction is §10's exported report form: a binary verdict and a stable
// reason.  It is a projection of RequirementResult and makes no new decision —
// it exists so a consumer outside the evaluator can act on the normative
// binary shape instead of parsing the three-valued internals.
type Satisfaction struct {
	Verdict SatisfactionVerdict `json:"verdict"`
	Reason  string              `json:"reason,omitempty"`
}

// Satisfaction collapses the three-valued evaluation into §10's binary report.
// A `violated` or an `unknown` both become UNSATISFIED; the reason is the first
// blocking cause in deterministic order, so `unknown` never reads as SATISFIED.
func (r RequirementResult) Satisfaction() Satisfaction {
	if r.Verdict == EvidenceSatisfied {
		return Satisfaction{Verdict: SatisfactionSatisfied}
	}
	if !r.Expression {
		return Satisfaction{Verdict: SatisfactionUnsatisfied, Reason: SatisfactionReasonExpressionFalse}
	}
	for _, c := range r.Constraints {
		if c.Verdict == EvidenceViolated || c.Verdict == EvidenceUnknown {
			return Satisfaction{Verdict: SatisfactionUnsatisfied, Reason: c.Reason}
		}
	}
	return Satisfaction{Verdict: SatisfactionUnsatisfied, Reason: SatisfactionReasonUnsatisfied}
}

// --- bounded expression parser (AEC §8 grammar) ---

type requirementExpr struct {
	ident string
	op    string // "AND" or "OR" when this is a binary node
	left  *requirementExpr
	right *requirementExpr
}

type requirementParser struct {
	tokens []string
	pos    int
	nodes  int
}

// parseRequirementExpression parses this profile's bounded expression grammar.
// It is the same shape as the Authorization Evidence Chain profile's expression
// (cited, not reproduced): a run of terms joined left to right by AND or OR —
// also spelled && and || — where a term is either a role name or a parenthesized
// expression, and a role name may contain letters, digits and the separators
// . : - _ .  The two operators bind equally, so parentheses are the only
// precedence mechanism.
//
// Reference: Schrock, "Authorization Evidence Chains", section 8 (expression
// grammar).
func parseRequirementExpression(in string) (*requirementExpr, error) {
	if strings.TrimSpace(in) == "" {
		return nil, fmt.Errorf("%w: empty expression", ErrRequirementExpression)
	}
	tokens, err := tokenizeRequirement(in)
	if err != nil {
		return nil, err
	}
	p := &requirementParser{tokens: tokens}
	expr, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected %q", ErrRequirementExpression, p.tokens[p.pos])
	}
	return expr, nil
}

func tokenizeRequirement(in string) ([]string, error) {
	var tokens []string
	i := 0
	for i < len(in) {
		switch c := in[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			tokens = append(tokens, string(c))
			i++
		case c == '&' || c == '|':
			// The grammar's symbolic operators are doubled; a single one is
			// not a token.
			if i+1 >= len(in) || in[i+1] != c {
				return nil, fmt.Errorf("%w: stray %q", ErrRequirementExpression, string(c))
			}
			tokens = append(tokens, string([]byte{c, c}))
			i += 2
		case isIdentByte(c):
			start := i
			for i < len(in) && isIdentByte(in[i]) {
				i++
			}
			tokens = append(tokens, in[start:i])
		default:
			return nil, fmt.Errorf("%w: unexpected character %q", ErrRequirementExpression, string(c))
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%w: empty expression", ErrRequirementExpression)
	}
	return tokens, nil
}

func isIdentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == ':' || c == '-' || c == '_':
		return true
	}
	return false
}

func (p *requirementParser) parseExpr(depth int) (*requirementExpr, error) {
	if depth > maxRequirementDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrRequirementShape, maxRequirementDepth)
	}
	left, err := p.parseTerm(depth)
	if err != nil {
		return nil, err
	}
	for p.pos < len(p.tokens) {
		op, ok := requirementOperator(p.tokens[p.pos])
		if !ok {
			break
		}
		p.pos++
		right, err := p.parseTerm(depth)
		if err != nil {
			return nil, err
		}
		p.nodes++
		if p.nodes > maxRequirementNodes {
			return nil, fmt.Errorf("%w: more than %d terms", ErrRequirementShape, maxRequirementNodes)
		}
		left = &requirementExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *requirementParser) parseTerm(depth int) (*requirementExpr, error) {
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("%w: unexpected end of expression", ErrRequirementExpression)
	}
	tok := p.tokens[p.pos]
	switch {
	case tok == "(":
		p.pos++
		inner, err := p.parseExpr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.tokens) || p.tokens[p.pos] != ")" {
			return nil, fmt.Errorf("%w: missing )", ErrRequirementExpression)
		}
		p.pos++
		return inner, nil
	case tok == ")" || requirementOperatorToken(tok):
		return nil, fmt.Errorf("%w: expected a term, got %q", ErrRequirementExpression, tok)
	default:
		p.pos++
		return &requirementExpr{ident: tok}, nil
	}
}

func requirementOperator(tok string) (string, bool) {
	switch tok {
	case "AND", "&&":
		return "AND", true
	case "OR", "||":
		return "OR", true
	}
	return "", false
}

func requirementOperatorToken(tok string) bool {
	_, ok := requirementOperator(tok)
	return ok
}

// eval applies the left-to-right, equal-binding rule.  An identifier with no
// eligible component evaluates to false (AEC §8).
func (e *requirementExpr) eval(present func(string) bool) bool {
	if e.op == "" {
		return present(e.ident)
	}
	if e.op == "AND" {
		return e.left.eval(present) && e.right.eval(present)
	}
	return e.left.eval(present) || e.right.eval(present)
}

func (e *requirementExpr) roles(set map[string]bool) {
	if e.op == "" {
		set[e.ident] = true
		return
	}
	e.left.roles(set)
	e.right.roles(set)
}
