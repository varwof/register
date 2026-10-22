// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"sort"

	"github.com/varwof/register/schemeadmin"
)

// Delta is the immutable CLC-CAPABILITY-CATALOG-DELTA-v1 artifact.  A delta is
// only meaningful against one exact base generation and digest, so a deployer
// never has to guess which snapshot a change was authored for.
type Delta struct {
	Version          string   `json:"@version"`
	Domain           string   `json:"domain"`
	CatalogID        string   `json:"catalog_id"`
	BaseGeneration   int64    `json:"base_generation"`
	TargetGeneration int64    `json:"target_generation"`
	BaseDigest       string   `json:"base_digest"`
	TargetDigest     string   `json:"target_digest"`
	IssuedAt         string   `json:"issued_at"`
	ValidUntil       string   `json:"valid_until"`
	Producer         string   `json:"producer"`
	Add              []Entry  `json:"add,omitempty"`
	Replace          []Entry  `json:"replace,omitempty"`
	Remove           []string `json:"remove,omitempty"`
}

// ParseDelta decodes exactly one closed delta object and validates it.
func ParseDelta(raw []byte) (*Delta, error) {
	var d Delta
	if err := decodeClosed(raw, &d); err != nil {
		return nil, fail(CodeDeltaShape, "%s", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks the delta's own shape.  Base matching needs the base catalog
// and happens in ApplyDelta.
func (d *Delta) Validate() error {
	if d.Version != DeltaVersion {
		return fail(CodeDeltaShape, "@version must be %q", DeltaVersion)
	}
	if !nameRe.MatchString(d.Domain) {
		return fail(CodeDeltaShape, "domain %q is not a catalog domain", d.Domain)
	}
	if !nameRe.MatchString(d.CatalogID) {
		return fail(CodeDeltaShape, "catalog_id %q is not a catalog identity", d.CatalogID)
	}
	if d.BaseGeneration < 1 {
		return fail(CodeDeltaShape, "base_generation must be >= 1")
	}
	if d.TargetGeneration != d.BaseGeneration+1 {
		return fail(CodeDeltaShape, "target_generation must be base_generation + 1")
	}
	if !digestRe.MatchString(d.BaseDigest) || !digestRe.MatchString(d.TargetDigest) {
		return fail(CodeDeltaShape, "base_digest and target_digest must be sha256 digests")
	}
	if !principalRe.MatchString(d.Producer) {
		return fail(CodeDeltaShape, "producer %q is not a principal", d.Producer)
	}
	issued, err := parseTime(d.IssuedAt)
	if err != nil {
		return fail(CodeDeltaShape, "issued_at: %s", err)
	}
	until, err := parseTime(d.ValidUntil)
	if err != nil {
		return fail(CodeDeltaShape, "valid_until: %s", err)
	}
	if !until.After(issued) {
		return fail(CodeDeltaShape, "valid_until must be after issued_at")
	}

	if len(d.Add) == 0 && len(d.Replace) == 0 && len(d.Remove) == 0 {
		return fail(CodeDeltaShape, "delta has no effect")
	}

	// A capability may appear in exactly one side of a delta.  Overlap would
	// make the result depend on application order.
	touched := make(map[string]string, len(d.Add)+len(d.Replace)+len(d.Remove))
	note := func(capability, side string) error {
		if capability == "" {
			return fail(CodeDeltaOperation, "%s names an empty capability", side)
		}
		if previous, ok := touched[capability]; ok {
			return fail(CodeDeltaOperation, "%q appears in both %s and %s", capability, previous, side)
		}
		touched[capability] = side
		return nil
	}
	for i := range d.Add {
		e := &d.Add[i]
		if err := e.validate(); err != nil {
			return err
		}
		if err := note(e.Capability, "add"); err != nil {
			return err
		}
	}
	for i := range d.Replace {
		e := &d.Replace[i]
		if err := e.validate(); err != nil {
			return err
		}
		if err := note(e.Capability, "replace"); err != nil {
			return err
		}
	}
	for _, capability := range d.Remove {
		if err := note(capability, "remove"); err != nil {
			return err
		}
	}
	return nil
}

// Apply checks the delta against base and returns the next catalog generation.
// The returned entries are ordered by capability, so the target digest does not
// depend on the order in which a producer happened to write the delta.
func Apply(base Catalog, d Delta) (*Catalog, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	baseDigest, err := base.Digest()
	if err != nil {
		return nil, fail(CodeDeltaBase, "%s", err)
	}
	if base.Domain != d.Domain || base.CatalogID != d.CatalogID {
		return nil, fail(CodeDeltaBase, "delta is for %s/%s, base is %s/%s", d.Domain, d.CatalogID, base.Domain, base.CatalogID)
	}
	if base.Generation != d.BaseGeneration {
		return nil, fail(CodeDeltaBase, "delta base generation %d, catalog is %d", d.BaseGeneration, base.Generation)
	}
	if baseDigest != d.BaseDigest {
		return nil, fail(CodeDeltaBase, "delta base digest %s, catalog is %s", d.BaseDigest, baseDigest)
	}

	existing := make(map[string]Entry, len(base.Entries))
	for _, e := range base.Entries {
		existing[e.Capability] = e
	}
	for _, capability := range d.Remove {
		if _, ok := existing[capability]; !ok {
			return nil, fail(CodeDeltaOperation, "remove names unknown capability %q", capability)
		}
		delete(existing, capability)
	}
	for _, e := range d.Replace {
		if _, ok := existing[e.Capability]; !ok {
			return nil, fail(CodeDeltaOperation, "replace names unknown capability %q", e.Capability)
		}
		existing[e.Capability] = e
	}
	for _, e := range d.Add {
		if _, ok := existing[e.Capability]; ok {
			return nil, fail(CodeDeltaOperation, "add names existing capability %q", e.Capability)
		}
		existing[e.Capability] = e
	}

	names := make([]string, 0, len(existing))
	for capability := range existing {
		names = append(names, capability)
	}
	sort.Strings(names)
	entries := make([]Entry, 0, len(names))
	for _, capability := range names {
		entries = append(entries, existing[capability])
	}

	next := Catalog{
		Version:        CatalogVersion,
		Domain:         base.Domain,
		CatalogID:      base.CatalogID,
		Generation:     d.TargetGeneration,
		IssuedAt:       d.IssuedAt,
		ValidUntil:     d.ValidUntil,
		PreviousDigest: baseDigest,
		// Apply is a pure transformation: it must not rewrite identity.  The
		// signed delta path separately requires d.Producer == base.Producer.
		Producer: base.Producer,
		Entries:  entries,
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	digest, err := next.Digest()
	if err != nil {
		return nil, fail(CodeDeltaDigest, "%s", err)
	}
	if digest != d.TargetDigest {
		return nil, fail(CodeDeltaDigest, "delta target digest %s, applied catalog is %s", d.TargetDigest, digest)
	}
	return &next, nil
}

// DeltaDigest returns the content address of the delta artifact.
func (d Delta) Digest() (string, error) {
	return schemeadmin.CanonicalDigest(d)
}
