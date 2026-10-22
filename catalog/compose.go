// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"crypto/x509"
	"sort"

	"github.com/varwof/register/semantics"
)

// VerifiedSource is one directory shard after detached-signature verification.
// The marker is unexported: a caller cannot label an unchecked catalog as
// verified without going through VerifySource.
type VerifiedSource struct {
	Name     string
	Catalog  Catalog
	Result   Result
	verified bool
}

// VerifySource verifies one source catalog with the same policy/state path as
// the single-directory loader.  A source name is required for required-shard
// accounting.
func VerifySource(name string, raw, signature []byte, roots []*x509.Certificate, policy TrustPolicy, state RegistryState) (VerifiedSource, error) {
	if name == "" {
		return VerifiedSource{}, fail(CodeShardMissing, "directory source name is required")
	}
	res, err := VerifySigned(raw, signature, roots, policy, state)
	if err != nil {
		return VerifiedSource{}, err
	}
	cat, err := ParseCatalog(raw)
	if err != nil {
		return VerifiedSource{}, err
	}
	return VerifiedSource{Name: name, Catalog: *cat, Result: res, verified: true}, nil
}

// CompositeCatalog is a deterministic merge of verified directory shards.  It
// is deliberately not a Catalog: it has no single publisher signature and must
// not be passed to VerifySigned/Accept as if it did.
type CompositeCatalog struct {
	Domain        string
	CatalogID     string
	Generation    int64
	Entries       []Entry
	Sources       []string
	SourceDigests map[string]string
}

// Entry returns the entry for a capability in a composite, or false.
func (c CompositeCatalog) Entry(capability string) (Entry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Capability == capability {
			return c.Entries[i], true
		}
	}
	return Entry{}, false
}

// ComposeVerified merges verified shards of one catalog identity.  Required
// source names must be present; every shard must be the same generation and
// digest.  Conflicting entries at the same capability are refused rather than
// resolved by source order.
func ComposeVerified(sources []VerifiedSource, required []string) (*CompositeCatalog, error) {
	if len(sources) == 0 {
		return nil, fail(CodeShardMissing, "at least one verified directory source is required")
	}
	seen := make(map[string]bool, len(sources))
	var out *CompositeCatalog
	byCapability := make(map[string]Entry)
	for _, src := range sources {
		if !src.verified {
			return nil, fail(CodeStateUnverified, "directory source %q is not verified", src.Name)
		}
		if seen[src.Name] {
			return nil, fail(CodeShardMissing, "duplicate directory source %q", src.Name)
		}
		seen[src.Name] = true
		c := src.Catalog
		if out == nil {
			out = &CompositeCatalog{
				Domain: c.Domain, CatalogID: c.CatalogID, Generation: c.Generation,
				Sources: []string{}, SourceDigests: map[string]string{},
			}
		} else if out.Domain != c.Domain || out.CatalogID != c.CatalogID {
			return nil, fail(CodeDirectoryConflict, "source %q is %s/%s, expected %s/%s", src.Name, c.Domain, c.CatalogID, out.Domain, out.CatalogID)
		} else if out.Generation != c.Generation {
			return nil, fail(CodeDirectoryConflict, "source %q generation %d, expected %d", src.Name, c.Generation, out.Generation)
		}
		out.Sources = append(out.Sources, src.Name)
		out.SourceDigests[src.Name] = src.Result.CatalogDigest
		for _, entry := range c.Entries {
			if prior, ok := byCapability[entry.Capability]; ok {
				if !sameEntry(prior, entry) {
					return nil, fail(CodeDirectoryConflict, "capability %q differs between directory shards", entry.Capability)
				}
				continue
			}
			byCapability[entry.Capability] = entry
			out.Entries = append(out.Entries, entry)
		}
	}
	sort.Strings(out.Sources)
	for _, name := range required {
		if !seen[name] {
			return nil, fail(CodeShardMissing, "required directory source %q is absent", name)
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Capability < out.Entries[j].Capability })
	return out, nil
}

func sameEntry(a, b Entry) bool {
	ra, errA := semantics.CanonicalJSON(a)
	rb, errB := semantics.CanonicalJSON(b)
	return errA == nil && errB == nil && string(ra) == string(rb)
}
