// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CapabilityClaim is a single AI-generated capability claim (pending validation/minimal privilege detection).
type CapabilityClaim struct {
	SchemeID   string         `json:"scheme_id"`  // vendor/product
	Capability string         `json:"capability"` // capability_id (may contain wildcards)
	Parameters map[string]any `json:"parameters,omitempty"`
	Rationale  string         `json:"rationale,omitempty"` // Authorization rationale from AI
}

// ClaimResult is the validation result for a single claim.
type ClaimResult struct {
	Claim CapabilityClaim
	Valid bool
	Error string // Reason when Valid=false
}

// MinSetReport is the complete report for minimal privilege validation.
type MinSetReport struct {
	// ValidClaims are valid and non-redundant claims.
	ValidClaims []CapabilityClaim
	// InvalidClaims are invalid claims (illegal capability/illegal parameters/unknown scheme).
	InvalidClaims []ClaimResult
	// RedundantClaims are claims covered by a wildcard or duplicated (recommended to remove).
	RedundantClaims []ClaimResult
	// MissingGranted are capabilities that are claimed but not covered by any role grant
	// (the AI-generated set references a capability not authorized for this identity).
	MissingGranted []string
	// AllowedPatterns are the grants actually held by the identity (wildcards expanded).
	AllowedPatterns []string
	// IsMinimal is true when the set is already minimal privilege.
	IsMinimal bool
}

// ParseCapabilityClaims parses a list of capability claims from JSON data.
// Expected structure: [{"scheme_id":"varwof/core","capability":"cert:issue",...}]
func ParseCapabilityClaims(data []byte) ([]CapabilityClaim, error) {
	var claims []CapabilityClaim
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("parse capability claims: %w", err)
	}
	for i, c := range claims {
		if c.SchemeID == "" || c.Capability == "" {
			return nil, fmt.Errorf("claim %d: scheme_id and capability are required", i)
		}
	}
	return claims, nil
}

// ValidateClaims validates capability claims: scheme exists, capability is legal (supports wildcards).
// Returns the result for each claim. Does not include minimal privilege detection.
func (r *Registry) ValidateClaims(claims []CapabilityClaim) []ClaimResult {
	results := make([]ClaimResult, 0, len(claims))
	for _, c := range claims {
		res := ClaimResult{Claim: c}
		def, ok := r.Get(c.SchemeID)
		if !ok {
			res.Error = fmt.Sprintf("unknown scheme %q", c.SchemeID)
			results = append(results, res)
			continue
		}
		ids := ListCapabilities(def)
		matched := false
		for _, id := range ids {
			if MatchCapability(id, c.Capability) {
				matched = true
				break
			}
		}
		if !matched {
			res.Error = fmt.Sprintf("capability %q not in scheme %s (available: %s)",
				c.Capability, c.SchemeID, strings.Join(ids, ", "))
			results = append(results, res)
			continue
		}
		// Parameter validity: claimed parameters must be within the capability's parameters definition
		if err := validateClaimParams(def, c); err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		res.Valid = true
		results = append(results, res)
	}
	return results
}

// validateClaimParams validates that all claimed parameters are within the capability definition.
func validateClaimParams(def *SchemeDefinition, c CapabilityClaim) error {
	if len(c.Parameters) == 0 {
		return nil
	}
	var entry *CapabilityEntry
	for i := range def.Capabilities {
		if def.Capabilities[i].ID == c.Capability {
			entry = &def.Capabilities[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("capability %q not found", c.Capability)
	}
	for k := range c.Parameters {
		if _, ok := entry.Parameters[k]; !ok {
			return fmt.Errorf("unknown parameter %q for %s (allowed: %s)",
				k, c.Capability, paramKeys(entry.Parameters))
		}
	}
	return nil
}

// CheckMinimalCapabilitySet performs minimal privilege validation:
//  1. Validate each claim's legality (scheme/capability/parameters)
//  2. Detect redundancy: covered by another wildcard claim, or completely duplicated
//  3. Detect over-privilege: claimed capabilities not within the identity's granted authorization scope
//  4. Determine whether minimal privilege has been achieved
//
// grantedPatterns are the grants actually held by the identity (e.g. role grants, may contain wildcards).
// Pass nil to skip over-privilege checking (only check legality and redundancy).
func (r *Registry) CheckMinimalCapabilitySet(claims []CapabilityClaim, grantedPatterns []string) *MinSetReport {
	rep := &MinSetReport{}
	validated := r.ValidateClaims(claims)
	for _, v := range validated {
		if !v.Valid {
			rep.InvalidClaims = append(rep.InvalidClaims, v)
			continue
		}
		rep.ValidClaims = append(rep.ValidClaims, v.Claim)
	}

	// Redundancy detection (only for valid claims)
	valid := rep.ValidClaims
	// Track which claims have been marked redundant to avoid duplicate marking
	redundantIdx := make(map[int]bool)
	for i, v := range valid {
		if redundantIdx[i] {
			continue
		}
		redundant := false
		// Covered by another claim's wildcard (v is a subset of other)
		for j, other := range valid {
			if i == j {
				continue
			}
			if other.SchemeID != v.SchemeID {
				continue
			}
			if isSubsetMatch(v.Capability, other.Capability) {
				redundant = true
				break
			}
		}
		if redundant {
			redundantIdx[i] = true
			rep.RedundantClaims = append(rep.RedundantClaims, ClaimResult{
				Claim: v,
				Error: "covered by a wildcard claim",
			})
		}
	}

	// Over-privilege detection
	if len(grantedPatterns) > 0 {
		for _, v := range valid {
			covered := false
			for _, g := range grantedPatterns {
				// grant may be "scheme:capability" or just "capability"
				if MatchCapability(v.SchemeID+":"+v.Capability, g) ||
					MatchCapability(v.Capability, g) {
					covered = true
					break
				}
			}
			if !covered {
				rep.MissingGranted = append(rep.MissingGranted, v.SchemeID+":"+v.Capability)
			}
		}
		rep.AllowedPatterns = grantedPatterns
	}

	// Minimal privilege determination
	rep.IsMinimal = len(rep.InvalidClaims) == 0 &&
		len(rep.RedundantClaims) == 0 &&
		len(rep.MissingGranted) == 0

	return rep
}

// isSubsetMatch checks if capability is covered by a grant wildcard (strict subset, excluding itself).
func isSubsetMatch(capability, grant string) bool {
	if grant == capability {
		return false
	}
	if MatchCapability(capability, grant) {
		return true
	}
	return false
}

func paramKeys(m map[string]ParameterDef) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
