// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Authorization sources — which artifacts the decision rested on.
//
// A verdict is only as good as the authority behind it, and a verdict that
// cannot name its sources cannot be re-appraised by anyone else.  The model
// here follows Action Evidence Graph (EP-AEG §2), which is the most explicit
// published treatment of the problem:
//
//   - every source is content-addressed: its id is the digest of the material,
//     so two parties holding the same artifact agree on the node;
//   - a relation between two sources is a *claim*, and a verifier MUST NOT
//     credit it unless the claim is present in the source artifact's own
//     (natively verified) bytes.  Here that means: a link from A to B is only
//     credited when A's References contain B's digest — a presenter cannot
//     assert a delegation its bytes do not contain;
//   - a claimed but unbacked relation is not "missing evidence", it is
//     deception, and it poisons the whole chain (ErrSourceEdgeUnbacked);
//   - the chain's identity is computed over the sorted node identities and the
//     sorted links, never over the inline material, so two parties with
//     different disclosures still agree on which chain they are discussing.
//
// CLC still does not implement containment (AEG's "does this delegation stay
// within its parent") — that belongs to the native artifact's verifier.  What
// the language provides is the reference structure, so a decision record can
// say *which* authority it stood on.

package semantics

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// SourceRef is one authorization-bearing artifact: a certificate, a token, an
// approval, a policy decision.
type SourceRef struct {
	// Kind names the artifact class, e.g. "aic-x509", "aic-jwt", "delegation",
	// "principal-cert", "policy-permit".
	Kind string `json:"kind"`
	// ID is a stable identifier within the kind (certificate serial, token
	// jti, approval id).
	ID string `json:"id"`
	// Issuer names who issued it, when that is meaningful.
	Issuer string `json:"issuer,omitempty"`
	// Digest is the hash of the artifact's natively verified material.
	Digest Digest `json:"digest"`
	// References are the digests this artifact's own bytes name — the exact
	// material backing an edge to another source.  A link whose target is not
	// listed here is unbacked and refused.
	References []Digest `json:"references,omitempty"`
}

// SourceLink is a claimed relation between two sources: From (the authority)
// names To (the artifact derived from it).
type SourceLink struct {
	From Digest `json:"from"`
	To   Digest `json:"to"`
}

// SourceChain is the set of sources a decision rested on, plus the relations
// claimed between them.
type SourceChain struct {
	Sources []SourceRef  `json:"sources"`
	Links   []SourceLink `json:"links,omitempty"`
}

var (
	// ErrSourceChainEmpty means a chain was supplied with no sources.
	ErrSourceChainEmpty = errors.New("source_chain_empty")
	// ErrSourceShape means a source is missing its kind/id/digest, or its
	// digest is not a usable algorithm-tagged value.
	ErrSourceShape = errors.New("source_shape")
	// ErrSourceDuplicate means two sources carry the same digest, which makes
	// the chain ambiguous.
	ErrSourceDuplicate = errors.New("source_duplicate")
	// ErrSourceDanglingLink means a link names a digest no source in the chain
	// carries: the referenced material was not disclosed.
	ErrSourceDanglingLink = errors.New("source_dangling_link")
	// ErrSourceEdgeUnbacked means a link claims a relation the source's own
	// bytes do not contain.  Absence is "not enough"; this is deception.
	ErrSourceEdgeUnbacked = errors.New("source_edge_unbacked")
	// ErrSourceChainCycle means the links do not form a simple path.
	ErrSourceChainCycle = errors.New("source_chain_cycle")
	// ErrSourceChainBranch means a walk was asked for on a source that names
	// more than one other source, so there is no single path to return.
	ErrSourceChainBranch = errors.New("source_chain_branch")
)

// Validate checks the chain's structure and, in particular, that every claimed
// relation is backed by the source's own references.
func (c SourceChain) Validate() error {
	if len(c.Sources) == 0 {
		return ErrSourceChainEmpty
	}
	byDigest := make(map[string]SourceRef, len(c.Sources))
	for _, s := range c.Sources {
		if s.Kind == "" || s.ID == "" {
			return fmt.Errorf("%w: kind/id required (got %q/%q)", ErrSourceShape, s.Kind, s.ID)
		}
		if !digestUsable(s.Digest) {
			return fmt.Errorf("%w: source %s/%s has no usable digest", ErrSourceShape, s.Kind, s.ID)
		}
		key := digestKey(s.Digest)
		if _, dup := byDigest[key]; dup {
			return fmt.Errorf("%w: %s", ErrSourceDuplicate, key)
		}
		byDigest[key] = s
	}

	edges := make(map[string][]string, len(c.Sources))
	for _, l := range c.Links {
		from, okFrom := byDigest[digestKey(l.From)]
		to, okTo := byDigest[digestKey(l.To)]
		if !okFrom || !okTo {
			return fmt.Errorf("%w: %s -> %s", ErrSourceDanglingLink, digestKey(l.From), digestKey(l.To))
		}
		if !referencesDigest(from.References, to.Digest) {
			return fmt.Errorf("%w: %s does not name %s", ErrSourceEdgeUnbacked, from.ID, to.ID)
		}
		edges[digestKey(from.Digest)] = append(edges[digestKey(from.Digest)], digestKey(to.Digest))
	}

	if err := detectCycle(byDigest, edges); err != nil {
		return err
	}
	return nil
}

func detectCycle(byDigest map[string]SourceRef, edges map[string][]string) error {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(byDigest))
	var visit func(string) error
	visit = func(node string) error {
		color[node] = grey
		for _, next := range edges[node] {
			switch color[next] {
			case grey:
				return fmt.Errorf("%w: %s", ErrSourceChainCycle, byDigest[next].ID)
			case white:
				if err := visit(next); err != nil {
					return err
				}
			}
		}
		color[node] = black
		return nil
	}
	for node := range edges {
		if color[node] == white {
			if err := visit(node); err != nil {
				return err
			}
		}
	}
	return nil
}

// Digest is the chain's identity: the sorted node identities plus the sorted
// links, hashed — never the inline material, so two parties holding different
// disclosures of the same chain agree on it (EP-AEG §2.3).
func (c SourceChain) Digest() (Digest, error) {
	if err := c.Validate(); err != nil {
		return Digest{}, err
	}
	type nodeID struct {
		Kind  string `json:"kind"`
		ID    string `json:"id"`
		Alg   string `json:"alg"`
		Value string `json:"value"`
	}
	nodes := make([]nodeID, 0, len(c.Sources))
	for _, s := range c.Sources {
		nodes = append(nodes, nodeID{Kind: s.Kind, ID: s.ID, Alg: s.Digest.Alg, Value: hex.EncodeToString(s.Digest.Value)})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		if nodes[i].ID != nodes[j].ID {
			return nodes[i].ID < nodes[j].ID
		}
		return nodes[i].Value < nodes[j].Value
	})
	links := make([]string, 0, len(c.Links))
	for _, l := range c.Links {
		links = append(links, digestKey(l.From)+"->"+digestKey(l.To))
	}
	sort.Strings(links)
	return DigestOf(struct {
		Sources []nodeID `json:"sources"`
		Links   []string `json:"links,omitempty"`
	}{Sources: nodes, Links: links})
}

// StandingOn returns the path an artifact stands on: the artifact first, then
// each source its own bytes name, ending at a source that names nothing (the
// authoritative root of this chain).
//
// The walk follows the "artifact names authority" direction (EP-AEG's
// byte-backed edge), so for `AIC contains the delegation, the delegation stands
// on the principal certificate` it returns [aic-x509, delegation,
// principal-cert].  A source that names more than one other source in the chain
// has no single path: that is ErrSourceChainBranch.
func (c SourceChain) StandingOn(from Digest) ([]SourceRef, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	byDigest := make(map[string]SourceRef, len(c.Sources))
	for _, s := range c.Sources {
		byDigest[digestKey(s.Digest)] = s
	}
	named := make(map[string][]SourceRef, len(c.Links))
	for _, l := range c.Links {
		named[digestKey(l.From)] = append(named[digestKey(l.From)], byDigest[digestKey(l.To)])
	}

	current, ok := byDigest[digestKey(from)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSourceDanglingLink, digestKey(from))
	}
	var path []SourceRef
	seen := make(map[string]bool, len(c.Sources))
	for {
		key := digestKey(current.Digest)
		if seen[key] {
			return nil, fmt.Errorf("%w: %s", ErrSourceChainCycle, current.ID)
		}
		seen[key] = true
		path = append(path, current)

		next := named[key]
		switch len(next) {
		case 0:
			return path, nil
		case 1:
			current = next[0]
		default:
			return nil, fmt.Errorf("%w: %s names %d sources", ErrSourceChainBranch, current.ID, len(next))
		}
	}
}

func digestUsable(d Digest) bool {
	return d.Alg != "" && len(d.Value) > 0
}

func digestKey(d Digest) string {
	return d.Alg + ":" + hex.EncodeToString(d.Value)
}

func referencesDigest(refs []Digest, want Digest) bool {
	for _, r := range refs {
		if r.Equal(want) {
			return true
		}
	}
	return false
}
