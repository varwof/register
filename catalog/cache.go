// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// DirectoryCache is a bounded local cache for one directory exchange endpoint.
// A fresh entry avoids a fetch; if a fetch fails the last valid bundle can be
// returned as stale, and the caller's normal VerifySigned freshness policy
// decides whether it is still admissible.  The cache never decides trust.
type DirectoryCache struct {
	mu       sync.Mutex
	bundle   DirectoryBundle
	fetched  time.Time
	TTL      time.Duration
	MaxStale time.Duration
}

// Fetch returns a cached bundle when fresh, otherwise fetches and caches it.
// stale reports that the returned bundle is the last successful fetch after a
// network failure; callers must still validate it.
func (c *DirectoryCache) Fetch(ctx context.Context, client *http.Client, base string, now time.Time) (DirectoryBundle, bool, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetched.IsZero() && c.TTL > 0 && now.Sub(c.fetched) < c.TTL {
		return c.bundle, true, false, nil
	}
	b, err := FetchDirectory(ctx, client, base)
	if err == nil {
		c.bundle = b
		c.fetched = now
		return b, false, false, nil
	}
	if !c.fetched.IsZero() && (c.MaxStale == 0 || now.Sub(c.fetched) <= c.MaxStale) {
		return c.bundle, true, true, nil
	}
	return DirectoryBundle{}, false, false, err
}
