// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/semantics"
)

// aecRequirement mirrors the fields of EP-AEC-REQUIREMENT-v1 in AEC §4.
// Unknown semantic members are rejected by Project rather than silently
// dropped; carrier obligations that CLC cannot evaluate are returned as
// RequiredNativeChecks.
type aecRequirement struct {
	Version         string         `json:"@version"`
	RequirementID   string         `json:"requirement_id"`
	Purpose         string         `json:"purpose"`
	Expression      string         `json:"expression"`
	FreshnessSec    map[string]int `json:"freshness_sec"`
	StatusRequired  []string       `json:"status_required"`
	RoleConstraints []struct {
		Type          string `json:"type"`
		ComponentType string `json:"component_type"`
		Threshold     int    `json:"threshold"`
		SubjectSource string `json:"subject_id_source"`
	} `json:"role_constraints"`
	RequiredBindings []struct {
		FromType string `json:"from_type"`
		Relation string `json:"relation"`
		ToType   string `json:"to_type"`
	} `json:"required_bindings"`
}

type clcConstraint struct {
	Role       string `json:"role"`
	Constraint string `json:"constraint"`
}

type clcRequirement struct {
	Version       string          `json:"@version"`
	RequirementID string          `json:"requirement_id"`
	Purpose       string          `json:"purpose,omitempty"`
	Expression    string          `json:"expression"`
	Constraints   []clcConstraint `json:"constraints,omitempty"`
}

type emiliaAEC struct{}

func (e *emiliaAEC) ID() string { return "emilia/ep-aec-requirement-v1" }

func (e *emiliaAEC) Match(raw []byte) bool {
	if err := jsonstrict.Check(raw); err != nil {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	v, _ := m["@version"].(string)
	return v == "EP-AEC-REQUIREMENT-v1"
}

func (e *emiliaAEC) Project(raw []byte, ctx Context) (ProjectedView, error) {
	if err := jsonstrict.Check(raw); err != nil {
		return ProjectedView{}, fmt.Errorf("invalid AEC JSON: %w", err)
	}
	// The source digest is taken over the complete document as received,
	// before any member is interpreted, dropped or rewritten.  Strict JSON
	// and JCS make it reproducible by any implementation holding the same
	// bytes.
	sourceDigest, err := sourceRequirementDigest(raw)
	if err != nil {
		return ProjectedView{}, err
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return ProjectedView{}, err
	}
	var a aecRequirement
	if err := json.Unmarshal(raw, &a); err != nil {
		return ProjectedView{}, err
	}

	out := clcRequirement{
		Version:       "CLC-REQUIREMENT-v1",
		RequirementID: a.RequirementID,
		Purpose:       a.Purpose,
		Expression:    a.Expression,
	}
	var residual []string
	unknown := append(unknownAECMembers(generic), unknownNestedAECMembers(generic)...)
	if len(unknown) != 0 {
		return ProjectedView{}, fmt.Errorf("unsupported AEC content: %s", strings.Join(unknown, "; "))
	}
	var nativeChecks []string
	var requiredCheckIDs []string

	roles := make([]string, 0, len(a.FreshnessSec))
	for r := range a.FreshnessSec {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	for _, r := range roles {
		role, err := pinnedRole(ctx.RoleMap, r)
		if err != nil {
			return ProjectedView{}, err
		}
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       role,
			Constraint: fmt.Sprintf("varwof/evidence-v1:freshness:sec:%d", a.FreshnessSec[r]),
		})
	}

	for _, rc := range a.RoleConstraints {
		if rc.Type != "distinct-subject-quorum" {
			return ProjectedView{}, fmt.Errorf("unsupported AEC role constraint %q", rc.Type)
		}
		role, err := pinnedRole(ctx.RoleMap, rc.ComponentType)
		if err != nil {
			return ProjectedView{}, err
		}
		if rc.SubjectSource != "native-verifier" {
			return ProjectedView{}, fmt.Errorf(
				"AEC role constraint subject_id_source must be native-verifier, got %q", rc.SubjectSource)
		}
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       role,
			Constraint: fmt.Sprintf("varwof/evidence-v1:quorum:distinct:%d", rc.Threshold),
		})
	}
	for _, r := range a.StatusRequired {
		// A status check runs over a component type, so the same relying-party
		// pin applies: an unpinned type is a refusal, not a free-form check id.
		if _, err := pinnedRole(ctx.RoleMap, r); err != nil {
			return ProjectedView{}, fmt.Errorf("AEC status_required: %w", err)
		}
		nativeChecks = append(nativeChecks, "status_required:"+r)
		requiredCheckIDs = append(requiredCheckIDs, "status_required:"+r)
	}
	expressionParts := []string{"(" + a.Expression + ")"}
	seenBindings := make(map[string]bool, len(a.RequiredBindings))
	for _, b := range a.RequiredBindings {
		role, err := BindingRoleName(b.FromType, b.Relation, b.ToType)
		if err != nil {
			return ProjectedView{}, err
		}
		if !seenBindings[role] {
			expressionParts = append(expressionParts, role)
			seenBindings[role] = true
		}
		nativeChecks = append(nativeChecks, "required_binding:"+b.FromType+":"+b.Relation+":"+b.ToType)
		residual = append(residual, fmt.Sprintf(
			"required_binding %s -%s-> %s: native verifier must emit derived role %s",
			b.FromType, b.Relation, b.ToType, role))
	}
	out.Expression = strings.Join(expressionParts, " AND ")

	reqBytes, err := json.Marshal(out)
	if err != nil {
		return ProjectedView{}, err
	}
	req, err := semantics.ParseRequirement(reqBytes)
	if err != nil {
		return ProjectedView{}, err
	}
	projectedDigest, err := req.Digest()
	if err != nil {
		return ProjectedView{}, err
	}

	meta := map[string]string{
		"projector_id":  e.ID(),
		"source_format": "EP-AEC-REQUIREMENT-v1",
		"mapped_at_utc": ctx.Now.UTC().Format(time.RFC3339),
	}
	if !ctx.Now.IsZero() {
		meta["project_ctx_now_utc"] = ctx.Now.UTC().Format(time.RFC3339)
	}
	if len(ctx.RoleMap) > 0 {
		keys := make([]string, 0, len(ctx.RoleMap))
		for k := range ctx.RoleMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			meta["role_map/"+k] = ctx.RoleMap[k]
		}
	}

	return ProjectedView{
		Requirement:                &req,
		SourceRequirementDigest:    &sourceDigest,
		ProjectedRequirementDigest: &projectedDigest,
		Facts:                      []semantics.EvidenceFact{},
		Residuals:                  residual,
		RequiredNativeChecks:       nativeChecks,
		RequiredCheckIDs:           requiredCheckIDs,
		Meta:                       meta,
	}, nil
}

// pinnedRole resolves an AEC role through the relying-party-pinned RoleMap.
// Identity mappings are explicit; an absent mapping is never guessed.
func pinnedRole(roleMap map[string]string, foreign string) (string, error) {
	if foreign == "" {
		return "", fmt.Errorf("AEC role identifier is empty")
	}
	mapped, ok := roleMap[foreign]
	if !ok || mapped == "" {
		return "", fmt.Errorf("AEC role %q has no pinned CLC role mapping", foreign)
	}
	return mapped, nil
}

// Binding encoding namespace and bounds.  The role is a reversible encoding,
// not a hash: a hash is collision-resistant but not mathematically injective,
// and two different triples must never share a role name.
const (
	bindingRolePrefix    = "clc:evidence-binding:"
	maxBindingRoleBytes  = 256
	maxBindingRolePartSz = maxBindingRoleBytes // guards the uint32 length fields
)

// BindingRoleName returns the CLC role representing one AEC required_bindings
// triple.  The complete ordered triple is encoded reversibly:
//
//	prefix || base64url_no_padding(uint32be(len(from)) || from ||
//	                               uint32be(len(relation)) || relation ||
//	                               uint32be(len(to)) || to)
//
// The length prefixes make the encoding injective even though `:` is legal
// inside a component.  Components must be non-empty, valid UTF-8 and drawn
// from the AEC identifier character set.  An encoding longer than 256 bytes is
// rejected, never truncated.
func BindingRoleName(fromType, relation, toType string) (string, error) {
	parts := []struct {
		field string
		value string
	}{
		{"from_type", fromType},
		{"relation", relation},
		{"to_type", toType},
	}
	payloadLen := 0
	for _, part := range parts {
		if len(part.value) > maxBindingRolePartSz {
			return "", fmt.Errorf("AEC required_bindings %s is too long", part.field)
		}
		if err := validateAECIdentifier(part.field, part.value); err != nil {
			return "", err
		}
		payloadLen += 4 + len(part.value)
	}
	payload := make([]byte, 0, payloadLen)
	for _, part := range parts {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(part.value)))
		payload = append(payload, part.value...)
	}
	role := bindingRolePrefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(role) > maxBindingRoleBytes {
		return "", fmt.Errorf(
			"AEC required_bindings %q -%s-> %q encodes to a %d-byte role; limit is %d",
			fromType, relation, toType, len(role), maxBindingRoleBytes)
	}
	return role, nil
}

// validateAECIdentifier applies the AEC identifier character set,
// 1*( ALPHA / DIGIT / "." / ":" / "-" / "_" ), and rejects empty or invalid
// UTF-8 values.  The check is byte-wise because the grammar is ASCII.
func validateAECIdentifier(field, value string) error {
	if value == "" {
		return fmt.Errorf("AEC required_bindings %s is empty", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("AEC required_bindings %s is not valid UTF-8", field)
	}
	for i := 0; i < len(value); i++ {
		if !isAECIdentifierByte(value[i]) {
			return fmt.Errorf(
				"AEC required_bindings %s %q contains a character outside the AEC identifier set",
				field, value)
		}
	}
	return nil
}

func isAECIdentifierByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == ':' || c == '-' || c == '_':
		return true
	}
	return false
}

var aecTopLevelMembers = map[string]bool{
	"@version": true, "requirement_id": true, "purpose": true, "expression": true,
	"freshness_sec": true, "status_required": true, "role_constraints": true,
	"required_bindings": true,
}

var aecRoleConstraintMembers = map[string]bool{
	"type": true, "component_type": true, "threshold": true, "subject_id_source": true,
}

var aecBindingMembers = map[string]bool{
	"from_type": true, "relation": true, "to_type": true,
}

// unknownAECMembers surfaces every top-level member this projection does not
// understand.  An embedded `authorized`/`verified` boolean is therefore never
// silently treated as absent.
func unknownAECMembers(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !aecTopLevelMembers[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("unknown member %q: not carried", k))
	}
	return out
}

// unknownNestedAECMembers checks the two arrays whose elements have a fixed
// schema.  A future/extra field is reported by path rather than dropped.
func unknownNestedAECMembers(m map[string]json.RawMessage) []string {
	var out []string
	if raw, ok := m["role_constraints"]; ok {
		var elems []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &elems); err == nil {
			for i, elem := range elems {
				keys := make([]string, 0)
				for k := range elem {
					if !aecRoleConstraintMembers[k] {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				for _, k := range keys {
					out = append(out, fmt.Sprintf("role_constraints[%d].%s: unknown member, not carried", i, k))
				}
			}
		}
	}
	if raw, ok := m["required_bindings"]; ok {
		var elems []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &elems); err == nil {
			for i, elem := range elems {
				keys := make([]string, 0)
				for k := range elem {
					if !aecBindingMembers[k] {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				for _, k := range keys {
					out = append(out, fmt.Sprintf("required_bindings[%d].%s: unknown member, not carried", i, k))
				}
			}
		}
	}
	return out
}
