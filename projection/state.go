// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/semantics"
)

// StateVersion is the persisted snapshot-state revision.
const StateVersion = "CLC-EVIDENCE-STATE-v1"

// StateFile is the canonical on-disk form of accepted snapshot state.
type StateFile struct {
	Version   string            `json:"@version"`
	Snapshots []SnapshotBinding `json:"snapshots"`
}

// MarshalState renders the accepted state as canonical JSON.  The bytes are
// deterministic so a deployer can sign or compare them.
func (s SnapshotState) MarshalState() ([]byte, error) {
	bindings := s.Bindings()
	if bindings == nil {
		bindings = []SnapshotBinding{}
	}
	return semantics.CanonicalJSON(StateFile{Version: StateVersion, Snapshots: bindings})
}

// ParseState decodes and validates a persisted state file.  A duplicate
// coordinate is refused rather than silently collapsed.
func ParseState(raw []byte) (SnapshotState, error) {
	if len(raw) > MaxReportBytes {
		return nil, fmt.Errorf("state is %d bytes, limit is %d", len(raw), MaxReportBytes)
	}
	if err := jsonstrict.Check(raw); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var file StateFile
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("state has trailing data")
	}
	if file.Version != StateVersion {
		return nil, fmt.Errorf("state @version %q is not %q", file.Version, StateVersion)
	}
	state := make(SnapshotState, len(file.Snapshots))
	for i, binding := range file.Snapshots {
		if binding.Source == "" {
			return nil, fmt.Errorf("state snapshot %d has no source", i)
		}
		if binding.ComponentType == "" {
			return nil, fmt.Errorf("state snapshot %d has no componentType", i)
		}
		if err := binding.EvidenceDigest.Validate(); err != nil {
			return nil, fmt.Errorf("state snapshot %d evidence digest: %w", i, err)
		}
		if binding.Generation < 1 {
			return nil, fmt.Errorf("state snapshot %d generation must be >= 1", i)
		}
		if err := binding.Digest.Validate(); err != nil {
			return nil, fmt.Errorf("state snapshot %d digest: %w", i, err)
		}
		key := snapshotKey(binding.Source, binding.ComponentType, binding.EvidenceDigest)
		if _, ok := state[key]; ok {
			return nil, fmt.Errorf("state repeats snapshot coordinate %q", key)
		}
		state[key] = binding
	}
	return state, nil
}
