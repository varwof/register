// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

// Index is a deterministic capability lookup index for one catalogue.  It
// keeps the source order for duplicate detection (which Validate already
// refuses) and shards by the first capability byte so a 100k-entry catalogue
// does not require a linear scan per lookup.
type Index struct {
	shards [256][]int
	byName map[string]int
}

// BuildIndex indexes a validated (or at least shape-checked) catalogue.
func BuildIndex(c Catalog) *Index {
	idx := &Index{byName: make(map[string]int, len(c.Entries))}
	for i := range c.Entries {
		entry := &c.Entries[i]
		if _, exists := idx.byName[entry.Capability]; exists {
			continue
		}
		idx.byName[entry.Capability] = i
		var key byte
		if len(entry.Capability) > 0 {
			key = entry.Capability[0]
		}
		idx.shards[key] = append(idx.shards[key], i)
	}
	return idx
}

// Lookup returns the entry for a capability.
func (i *Index) Lookup(c Catalog, capability string) (Entry, bool) {
	if i == nil {
		return Entry{}, false
	}
	idx, ok := i.byName[capability]
	if !ok || idx < 0 || idx >= len(c.Entries) {
		return Entry{}, false
	}
	return c.Entries[idx], true
}

// Shard returns the entry positions in the first-byte shard, for diagnostics
// and scale tests.  The returned slice is owned by the index.
func (i *Index) Shard(capability string) []int {
	if i == nil || capability == "" {
		return nil
	}
	return i.shards[capability[0]]
}
