// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds all loaded scheme definitions.
type Registry struct {
	mu      sync.RWMutex
	schemes map[string]*SchemeDefinition
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{schemes: make(map[string]*SchemeDefinition)}
}

// Register adds a scheme definition. Overwrites if scheme_id already exists.
func (r *Registry) Register(def *SchemeDefinition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemes[def.SchemeID] = def
}

// Get returns a scheme definition by scheme_id.
func (r *Registry) Get(schemeID string) (*SchemeDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.schemes[schemeID]
	return def, ok
}

// Has checks if a scheme_id is registered.
func (r *Registry) Has(schemeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.schemes[schemeID]
	return ok
}

// HasCapability checks if a specific capability is registered.
func (r *Registry) HasCapability(schemeID, capID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.schemes[schemeID]
	if !ok {
		return false
	}
	for _, c := range def.Capabilities {
		if c.ID == capID {
			return true
		}
	}
	return false
}

// ValidateCapability checks if "scheme:cap_id" is valid and returns the entry.
func (r *Registry) ValidateCapability(formatted string) (*SchemeDefinition, *CapabilityEntry, error) {
	schemeID, capID, ok := ParseCapability(formatted)
	if !ok {
		return nil, nil, fmt.Errorf("invalid format: %s (expected scheme:capability_id)", formatted)
	}
	def, ok := r.Get(schemeID)
	if !ok {
		return nil, nil, fmt.Errorf("unknown scheme: %s", schemeID)
	}
	for i, c := range def.Capabilities {
		if c.ID == capID {
			return def, &def.Capabilities[i], nil
		}
	}
	return nil, nil, fmt.Errorf("unknown capability: %s in scheme %s", capID, schemeID)
}

// SchemeIDs returns all registered scheme_ids, sorted.
func (r *Registry) SchemeIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.schemes))
	for id := range r.schemes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Summary returns a human-readable summary of all registered schemes.
func (r *Registry) Summary() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.SchemeIDs()
	result := fmt.Sprintf("Capability Register: %d scheme(s) registered\n", len(ids))
	for _, id := range ids {
		def := r.schemes[id]
		result += fmt.Sprintf("  %s (%s) v%s — %d capability(ies)\n", def.Name, id, def.Version, len(def.Capabilities))
	}
	return result
}
