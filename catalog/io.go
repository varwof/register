// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/register/semantics"
)

// LoadCatalog reads and validates one catalog file.  It also returns the exact
// bytes, because the detached signature is over those bytes rather than over a
// re-serialization.
func LoadCatalog(path string) (*Catalog, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	c, err := ParseCatalog(raw)
	if err != nil {
		return nil, raw, err
	}
	return c, raw, nil
}

// LoadDelta reads and validates one delta file.
func LoadDelta(path string) (*Delta, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	d, err := ParseDelta(raw)
	if err != nil {
		return nil, raw, err
	}
	return d, raw, nil
}

// LoadPolicy reads a closed deployer policy file.
func LoadPolicy(path string) (TrustPolicy, error) {
	var p TrustPolicy
	if path == "" {
		return p, fmt.Errorf("policy path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if len(raw) > maxArtifactBytes {
		return p, fmt.Errorf("policy is %d bytes, limit is %d", len(raw), maxArtifactBytes)
	}
	if err := decodeClosed(raw, &p); err != nil {
		return p, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

// LoadState reads a closed local generation state.  An empty path means
// "nothing accepted yet".
func LoadState(path string) (RegistryState, error) {
	var s RegistryState
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if len(raw) > maxArtifactBytes {
		return s, fmt.Errorf("state is %d bytes, limit is %d", len(raw), maxArtifactBytes)
	}
	if err := decodeClosed(raw, &s); err != nil {
		return s, fmt.Errorf("state: %w", err)
	}
	return s, nil
}

// CanonicalBytes returns the file form written by the generators: the JCS
// encoding plus one trailing newline.  It is deterministic, so two deployers
// generating the same catalog produce byte-identical files to sign.
func CanonicalBytes(c Catalog) ([]byte, error) {
	raw, err := semantics.CanonicalJSON(c)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// WriteFile writes a complete artifact.  Without replace it refuses an
// existing path; with replace it writes a temp file in the same directory,
// fsyncs it and atomically links/renames it into place, so a crash cannot
// leave a partially written immutable artifact.
func WriteFile(path string, raw []byte, replace bool) error {
	return writeFileMode(path, raw, replace, 0o644)
}

// WriteStateFile writes a registry/snapshot state file: same atomic replace as
// WriteFile, but 0600 because the state is the local rollback anchor and does
// not need to be readable by other local users.
func WriteStateFile(path string, raw []byte, replace bool) error {
	return writeFileMode(path, raw, replace, 0o600)
}

func writeFileMode(path string, raw []byte, replace bool, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if replace {
		return os.Rename(tmp, path)
	}
	// Link is atomic and fails if path already exists, so the target is never
	// a partially written file.
	return os.Link(tmp, path)
}
