// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/varwof/register/semantics"
)

// aecRequirement mirrors the EP-AEC-REQUIREMENT-v1 example in AEC §4.  Only
// the members this projection understands are decoded; everything else is
// reported as a residual by name, never silently dropped.
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
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	v, _ := m["@version"].(string)
	return v == "EP-AEC-REQUIREMENT-v1"
}

func (e *emiliaAEC) Project(raw []byte, ctx Context) (ProjectedView, error) {
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
	residual = append(residual, unknownAECMembers(generic)...)
	residual = append(residual, unknownNestedAECMembers(generic)...)

	roles := make([]string, 0, len(a.FreshnessSec))
	for r := range a.FreshnessSec {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	for _, r := range roles {
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       r,
			Constraint: fmt.Sprintf("varwof/evidence-v1:freshness:sec:%d", a.FreshnessSec[r]),
		})
	}

	for _, rc := range a.RoleConstraints {
		if rc.Type != "distinct-subject-quorum" {
			residual = append(residual, "role_constraint "+rc.Type+": not expressible")
			continue
		}
		role, mapped := bridgeRole(ctx.RoleMap, rc.ComponentType)
		if rc.ComponentType != "" && !mapped {
			residual = append(residual,
				fmt.Sprintf("role_constraint component_type %q: no pinned role mapping, kept verbatim", rc.ComponentType))
		}
		if role == "" {
			role = rc.ComponentType
		}
		if role == "" {
			residual = append(residual, "role_constraint distinct-subject-quorum: no component_type, dropped")
			continue
		}
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       role,
			Constraint: fmt.Sprintf("varwof/evidence-v1:quorum:distinct:%d", rc.Threshold),
		})
		if rc.SubjectSource != "" {
			residual = append(residual, "subject_id_source="+rc.SubjectSource+": carrier-owned")
		}
	}
	for _, r := range a.StatusRequired {
		residual = append(residual, "status_required["+r+"]: carrier-owned, no CLC constraint")
	}
	for _, b := range a.RequiredBindings {
		residual = append(residual, fmt.Sprintf(
			"required_binding %s -%s-> %s: a relation between facts is not expressible",
			b.FromType, b.Relation, b.ToType))
	}

	reqBytes, err := json.Marshal(out)
	if err != nil {
		return ProjectedView{}, err
	}
	req, err := semantics.ParseRequirement(reqBytes)
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
		Requirement: &req,
		Facts:       []semantics.EvidenceFact{},
		Residuals:   residual,
		Meta:        meta,
	}, nil
}

// bridgeRole applies a pinned role mapping.  The second result reports whether
// the identifier was actually bridged (an identity entry still counts: the
// relying party pinned that name).
func bridgeRole(roleMap map[string]string, foreign string) (string, bool) {
	if foreign == "" {
		return "", false
	}
	if mapped, ok := roleMap[foreign]; ok && mapped != "" {
		return mapped, true
	}
	return foreign, false
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
