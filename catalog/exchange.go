// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DirectoryBundle is the input-only exchange shape for one catalog generation:
// an exact signed snapshot and an optional signed delta.  It carries bytes, not
// a verdict; Apply re-verifies whatever it consumes.
type DirectoryBundle struct {
	Snapshot          []byte
	SnapshotSignature []byte
	Delta             []byte
	DeltaSignature    []byte
}

// Handler serves the bundle at fixed paths.  It executes nothing and performs
// no trust decision; consumers still call Apply with local policy/state.
func (b DirectoryBundle) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/catalog":
			body = b.Snapshot
		case "/catalog.p7s":
			body = b.SnapshotSignature
		case "/delta":
			body = b.Delta
		case "/delta.p7s":
			body = b.DeltaSignature
		default:
			http.NotFound(w, r)
			return
		}
		if len(body) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(body)
	})
}

// FetchDirectory reads the fixed exchange endpoints from base.  It intentionally
// does not follow redirects or accept unbounded bodies.
func FetchDirectory(ctx context.Context, client *http.Client, base string) (DirectoryBundle, error) {
	if client == nil {
		client = http.DefaultClient
	}
	base = strings.TrimRight(base, "/")
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("directory %s: HTTP %d", path, resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > maxArtifactBytes {
			return nil, fmt.Errorf("directory %s: response exceeds %d bytes", path, maxArtifactBytes)
		}
		return raw, nil
	}
	b := DirectoryBundle{}
	var err error
	if b.Snapshot, err = get("/catalog"); err != nil {
		return b, err
	}
	if b.SnapshotSignature, err = get("/catalog.p7s"); err != nil {
		return b, err
	}
	if b.Delta, err = get("/delta"); err != nil {
		return b, err
	}
	if b.DeltaSignature, err = get("/delta.p7s"); err != nil {
		return b, err
	}
	if len(b.Snapshot) == 0 || len(b.SnapshotSignature) == 0 {
		return b, fail(CodeCatalogShape, "directory has no signed snapshot")
	}
	return b, nil
}

// Apply tries the delta first when present; if it cannot be applied, it falls
// back to the signed full snapshot and only accepts that snapshot through the
// normal state machine.  The bool reports whether the delta was used.
func (b DirectoryBundle) Apply(base Catalog, roots []*x509.Certificate, policy TrustPolicy, state RegistryState) (Result, *Catalog, bool, error) {
	if len(b.Delta) > 0 {
		res, next, err := VerifySignedDeltaWithState(b.Delta, b.DeltaSignature, base, roots, policy, state)
		if err == nil {
			return res, next, true, nil
		}
		// Fall through to the full immutable snapshot: a delta that cannot be
		// applied is never guessed at.
	}
	res, err := VerifySigned(b.Snapshot, b.SnapshotSignature, roots, policy, state)
	if err != nil {
		return res, nil, false, err
	}
	cat, err := ParseCatalog(b.Snapshot)
	if err != nil {
		return res, nil, false, err
	}
	nextState, err := state.Accept(*cat, res)
	if err != nil {
		return res, nil, false, err
	}
	_ = nextState
	return res, cat, false, nil
}
