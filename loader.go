package register

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadFromFS loads all capability JSON files from an embedded filesystem.
func LoadFromFS(fsys fs.FS) (map[string]*SchemeDefinition, error) {
	schemes := make(map[string]*SchemeDefinition)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if filepath.Ext(path) != ".json" || len(base) < 3 || base[0] != 'v' {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var def SchemeDefinition
		if err := json.Unmarshal(data, &def); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if def.SchemeID == "" {
			return fmt.Errorf("scheme_id required in %s", path)
		}
		if err := ValidateSchemeID(def.SchemeID); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		schemes[def.SchemeID] = &def
		return nil
	})
	return schemes, err
}

// LoadEmbedded is removed: capability data now lives in the separate
// capability module and is loaded from a directory on disk. Use
// LoadFromDir or LoadFromBoth with a path into the capability data tree.
func LoadEmbedded() (map[string]*SchemeDefinition, error) {
	return nil, fmt.Errorf("register: embedded schemes removed; configure capability_schemes to point at capability data directory")
}

// LoadFromDir loads all capability JSON files from a directory tree on disk.
// Expected structure: root/vendor/product/v*.json
func LoadFromDir(root string) (map[string]*SchemeDefinition, error) {
	schemes := make(map[string]*SchemeDefinition)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if filepath.Ext(path) != ".json" || len(base) < 3 || base[0] != 'v' {
			return nil
		}
		def, err := LoadScheme(path)
		if err != nil {
			return err
		}
		schemes[def.SchemeID] = def
		return nil
	})
	return schemes, err
}

// LoadFromBoth requires a non-empty disk directory. Embedded schemes are
// gone; disk is the only source. An empty dir returns an error.
func LoadFromBoth(diskDir string) (map[string]*SchemeDefinition, error) {
	if diskDir == "" {
		return nil, fmt.Errorf("register: capability_schemes directory required (embedded schemes removed)")
	}
	return LoadFromDir(diskDir)
}

// NewRegistryWithEmbedded is removed. Use NewRegistryFromDisk instead.
func NewRegistryWithEmbedded() (*Registry, error) {
	return nil, fmt.Errorf("register: NewRegistryWithEmbedded removed; use NewRegistryFromDisk")
}

// NewRegistryFromDisk creates a registry pre-loaded with schemes from a
// directory into the capability data tree.
func NewRegistryFromDisk(dir string) (*Registry, error) {
	schemes, err := LoadFromDir(dir)
	if err != nil {
		return nil, err
	}
	reg := NewRegistry()
	for _, def := range schemes {
		reg.Register(def)
	}
	return reg, nil
}

// NewRegistryFromBoth requires a non-empty disk directory and creates a
// registry pre-loaded from it.
func NewRegistryFromBoth(diskDir string) (*Registry, error) {
	schemes, err := LoadFromBoth(diskDir)
	if err != nil {
		return nil, err
	}
	reg := NewRegistry()
	for _, def := range schemes {
		reg.Register(def)
	}
	return reg, nil
}
