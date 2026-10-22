// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"reflect"
	"sync"
)

var (
	mu         sync.RWMutex
	projectors []Projector
)

// Register adds a projector.  A nil (including a typed-nil pointer) projector or
// a duplicate non-empty ID is ignored: a later registration must not shadow an
// established mapping.
func Register(p Projector) {
	if isNilProjector(p) {
		return
	}
	id := p.ID()
	if id == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, existing := range projectors {
		if existing.ID() == id {
			return
		}
	}
	projectors = append(projectors, p)
}

func isNilProjector(p Projector) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func Find(raw []byte) Projector {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range projectors {
		if isNilProjector(p) {
			continue
		}
		if p.Match(raw) {
			return p
		}
	}
	return nil
}

func List() []Projector {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Projector, 0, len(projectors))
	for _, p := range projectors {
		if !isNilProjector(p) {
			out = append(out, p)
		}
	}
	return out
}
