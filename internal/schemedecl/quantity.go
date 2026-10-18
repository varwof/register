// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package schemedecl implements the CLC-1.19 scheme declaration pilot: the
// `quantity` domain and the declaration validation it depends on.
//
// The pilot deliberately stays outside the core comparison code.  A declaration
// is applied as a *normalization layer*: each declared `quantity` value is
// checked against the declaration's fixed unit and rewritten as its normalized
// number before the ordinary CLC relations run.  That keeps `Entails` and
// `Contains` untouched while making the new domain testable end to end.
package schemedecl

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/varwof/register/semantics"
)

// Param is one declared parameter.
type Param struct {
	Domain   string `json:"domain"`
	Unit     string `json:"unit,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

// Capability is one capability's parameter declarations.
type Capability struct {
	Params map[string]Param `json:"params"`
}

// Declaration is a CLC-SCHEME-v1 artifact.
type Declaration struct {
	Version         string                `json:"@version"`
	Scheme          string                `json:"scheme"`
	DeclarationID   string                `json:"declaration_id"`
	CLCRevision     string                `json:"clc_revision"`
	Digest          string                `json:"digest"`
	Capabilities    map[string]Capability `json:"capabilities"`
	ConstraintTypes []string              `json:"constraint_types,omitempty"`
}

var knownDomains = map[string]bool{
	"bound": true, "enum": true, "exact": true,
	"quantity": true, "decimal-string": true, "subdomain": true, "path-prefix": true,
}

// Load reads a declaration file.
func Load(path string) (*Declaration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Declaration
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Validate checks the closed shape, the known domains, the quantity unit rule
// and the digest.
func (d *Declaration) Validate() error {
	if d.Version != "CLC-SCHEME-v1" {
		return fmt.Errorf("unsupported_declaration: %q", d.Version)
	}
	if d.Scheme == "" || d.DeclarationID == "" || d.CLCRevision == "" {
		return fmt.Errorf("invalid_declaration: missing scheme/declaration_id/clc_revision")
	}
	if len(d.Capabilities) == 0 {
		return fmt.Errorf("invalid_declaration: no capabilities")
	}
	for capName, c := range d.Capabilities {
		for pName, p := range c.Params {
			if !knownDomains[p.Domain] {
				return fmt.Errorf("unsupported_domain: %s.%s = %q", capName, pName, p.Domain)
			}
			if p.Domain == "quantity" && p.Unit == "" {
				return fmt.Errorf("invalid_declaration: %s.%s is quantity without unit", capName, pName)
			}
			if p.Domain != "quantity" && p.Unit != "" {
				return fmt.Errorf("invalid_declaration: %s.%s has unit outside quantity", capName, pName)
			}
		}
	}
	if d.Digest != "" {
		want, err := d.computeDigest()
		if err != nil {
			return err
		}
		if want != d.Digest {
			return fmt.Errorf("declaration_digest_mismatch: want %s, got %s", want, d.Digest)
		}
	}
	return nil
}

// computeDigest is sha256 over the declaration's JCS form without the digest
// member.  Go marshals map keys in sorted order, which for the ASCII member
// names of this artifact is the JCS order.
func (d *Declaration) computeDigest() (string, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	delete(m, "digest")
	canonical, err := json.Marshal(m) // map keys are marshaled in sorted order
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// param returns the declaration for one capability parameter.
func (d *Declaration) param(capability, name string) (Param, bool) {
	c, ok := d.Capabilities[capability]
	if !ok {
		return Param{}, false
	}
	p, ok := c.Params[name]
	return p, ok
}

// domainMap builds the semantics-level declaration for one capability.
func (d *Declaration) domainMap(capability string) semantics.DomainMap {
	c, ok := d.Capabilities[capability]
	if !ok {
		return nil
	}
	dm := make(semantics.DomainMap, len(c.Params))
	for name, p := range c.Params {
		dm[name] = semantics.DomainSpec{Name: p.Domain, Unit: p.Unit}
	}
	return dm
}

// Authorize applies the declaration's quantity normalization, then runs the
// ordinary multi-grant authorization.
func (d *Declaration) Authorize(capability string, grants []semantics.Grant, op semantics.Operation) semantics.Decision {
	return semantics.AuthorizeSetWithDomains(grants, op, d.domainMap(capability))
}

// Contains applies the same normalization and then the ordinary relation.  A
// unit mismatch is a containment failure (`params_not_narrower`), per §13.4.3.
func (d *Declaration) Contains(capability string, parent, child semantics.Grant) (bool, string) {
	dm := d.domainMap(capability)
	r := semantics.ContainsWithDomains(parent, child, dm, dm)
	return r.Contains, r.Reason
}

// DigestOf computes the declaration's digest for a raw object (test helper).
func DigestOf(raw []byte) (string, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return "", err
	}
	delete(m, "digest")
	enc, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(enc)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
