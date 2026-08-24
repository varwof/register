// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidationError describes a single validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult holds the outcome of validating a set of capabilities.
type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []string
	Checked  int
}

// ValidateCapabilities validates a list of "scheme:cap_id" strings against the registry.
func (r *Registry) ValidateCapabilities(caps []string) *ValidationResult {
	result := &ValidationResult{Valid: true}
	for _, cap := range caps {
		result.Checked++
		schemeID, capID, ok := ParseCapability(cap)
		if !ok {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   cap,
				Message: "invalid format (expected scheme:capability_id)",
			})
			continue
		}

		def, ok := r.Get(schemeID)
		if !ok {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   cap,
				Message: fmt.Sprintf("unknown scheme %q", schemeID),
			})
			continue
		}

		found := false
		for _, c := range def.Capabilities {
			if c.ID == capID {
				found = true
				break
			}
		}
		if !found {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   cap,
				Message: fmt.Sprintf("unknown capability %q in scheme %q", capID, schemeID),
			})
		}
	}
	return result
}

// CheckSubset checks if declared capabilities are a subset of allowed capabilities.
// Returns denied capabilities that are not in the allowed set.
func (r *Registry) CheckSubset(declared, allowed []string) (denied []string) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[strings.ToLower(a)] = true
	}
	for _, d := range declared {
		if !allowedSet[strings.ToLower(d)] {
			denied = append(denied, d)
		}
	}
	return denied
}

// CheckIntersection returns capabilities present in both sets.
func (r *Registry) CheckIntersection(setA, setB []string) (common []string) {
	setBMap := make(map[string]bool, len(setB))
	for _, b := range setB {
		setBMap[strings.ToLower(b)] = true
	}
	for _, a := range setA {
		if setBMap[strings.ToLower(a)] {
			common = append(common, a)
		}
	}
	return common
}

// FilterByScheme returns only capabilities belonging to a specific scheme.
func FilterByScheme(caps []string, schemeID string) []string {
	prefix := schemeID + ":"
	var result []string
	for _, c := range caps {
		if strings.HasPrefix(strings.ToLower(c), strings.ToLower(prefix)) {
			result = append(result, c)
		}
	}
	return result
}

// MatchCapability checks if a capability id matches a pattern (glob semantics).
// Supports: exact match, *, ?, a:b:* prefix wildcards. Same semantics as pki-types MatchCapability.
func MatchCapability(id, pattern string) bool {
	if id == pattern {
		return true
	}
	if pattern == "**" || pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(pattern, id)
	if ok {
		return ok
	}
	if len(pattern) >= 2 && pattern[len(pattern)-1] == '*' && pattern[len(pattern)-2] == ':' {
		prefix := pattern[:len(pattern)-1]
		return len(id) >= len(prefix) && id[:len(prefix)] == prefix
	}
	return false
}

// ValidateRoles validates that all role grants in a scheme are covered by capabilities.
// Returns uncovered grants (wildcards expanded against capabilities for validation).
// Use case: ensure role grants are all legal capabilities before gen-authz generates authz.json.
func (r *Registry) ValidateRoles(schemeID string) ([]string, error) {
	def, ok := r.Get(schemeID)
	if !ok {
		return nil, fmt.Errorf("unknown scheme: %s", schemeID)
	}
	ids := ListCapabilities(def)
	var uncovered []string
	for role, rd := range def.Roles {
		for _, g := range rd.Grants {
			covered := false
			for _, id := range ids {
				if MatchCapability(id, g) {
					covered = true
					break
				}
			}
			if !covered {
				uncovered = append(uncovered, fmt.Sprintf("%s:%s", role, g))
			}
		}
	}
	return uncovered, nil
}

// RoleGrantCovered checks if a single grant is covered by the scheme's capabilities (wildcard expanded).
func (r *Registry) RoleGrantCovered(schemeID, grant string) bool {
	def, ok := r.Get(schemeID)
	if !ok {
		return false
	}
	ids := ListCapabilities(def)
	for _, id := range ids {
		if MatchCapability(id, grant) {
			return true
		}
	}
	return false
}

// Deduplicate removes duplicate capabilities from a list.
func Deduplicate(caps []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, c := range caps {
		key := strings.ToLower(c)
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}
