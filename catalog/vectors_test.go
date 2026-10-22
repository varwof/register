// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/pkcs7"
	pki "github.com/varwof/types"

	"github.com/varwof/register/catalog"
)

// The corpus lives in the sibling capability repository.  CI for this module
// does not check that repository out, so a missing corpus skips the
// corpus-backed tests instead of failing them; the conformance workflow clones
// capability and runs the full set.
var catalogVectorCandidates = []string{
	"../capability/data/_vectors/catalog-v1/catalog-vectors.json",
	"../../capability/data/_vectors/catalog-v1/catalog-vectors.json",
}

func catalogVectorPath(t *testing.T) string {
	t.Helper()
	for _, p := range catalogVectorCandidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("catalog corpus not found in %v (capability checkout absent); skipping", catalogVectorCandidates)
	return ""
}

func catalogDeclarationPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(catalogVectorPath(t)), "declaration.json")
}

type corpus struct {
	Version           string                           `json:"@version"`
	ObservedAt        string                           `json:"observed_at"`
	Declaration       string                           `json:"declaration"`
	DeclarationDigest string                           `json:"declaration_digest"`
	Roots             map[string]string                `json:"roots"`
	Publishers        map[string]publisherSpec         `json:"publishers"`
	Policies          map[string]json.RawMessage       `json:"policies"`
	States            map[string]catalog.RegistryState `json:"states"`
	Catalogs          map[string]json.RawMessage       `json:"catalogs"`
	Deltas            map[string]json.RawMessage       `json:"deltas"`
	Discoveries       map[string]json.RawMessage       `json:"discoveries"`
	Vectors           []vector                         `json:"vectors"`
}

type publisherSpec struct {
	Seed         string      `json:"seed"`
	Principal    string      `json:"principal"`
	TrustRoot    string      `json:"trust_root"`
	HasAIC       *bool       `json:"has_aic"`
	Capabilities []grantSpec `json:"capabilities"`
}

type grantSpec struct {
	SchemeID     string         `json:"scheme_id"`
	CapabilityID string         `json:"capability_id"`
	Parameters   map[string]any `json:"parameters,omitempty"`
}

type vector struct {
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	Catalog     string      `json:"catalog"`
	Publisher   string      `json:"publisher"`
	Policy      string      `json:"policy"`
	State       string      `json:"state"`
	Roots       string      `json:"roots"`
	Delta       string      `json:"delta"`
	Discovery   string      `json:"discovery"`
	Expectation expectation `json:"expect"`
}

type expectation struct {
	OK         bool   `json:"ok"`
	Reason     string `json:"reason"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
	Note       string `json:"note"`
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	raw, err := os.ReadFile(catalogVectorPath(t))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if c.Version != "CLC-CATALOG-VECTORS-v1" {
		t.Fatalf("corpus version %q", c.Version)
	}
	return c
}

// fixtures materializes every named publisher once, because x509 certificate
// creation is not reproducible and later probe bundles need the exact DER.
type fixtures struct {
	roots  map[string]*x509.Certificate
	certs  map[string]*x509.Certificate
	decl   []byte
	policy map[string]catalog.TrustPolicy
	corpus corpus
}

func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	c := loadCorpus(t)

	declRaw, err := os.ReadFile(catalogDeclarationPath(t))
	if err != nil {
		t.Fatalf("read declaration: %v", err)
	}
	if got := catalog.DigestOfDeclaration(declRaw); got != c.DeclarationDigest {
		t.Fatalf("declaration digest %s, corpus pins %s", got, c.DeclarationDigest)
	}

	f := &fixtures{roots: map[string]*x509.Certificate{}, certs: map[string]*x509.Certificate{}, decl: declRaw, corpus: c}
	caCert, caKey := newCA(t, c.Roots["ca"])
	foreignCert, foreignKey := newCA(t, c.Roots["foreign"])
	f.roots["ca"] = caCert
	f.roots["foreign"] = foreignCert

	for name, spec := range c.Publishers {
		issuer, key := caCert, caKey
		if spec.TrustRoot == "foreign" {
			issuer, key = foreignCert, foreignKey
		}
		f.certs[name] = newPublisher(t, issuer, key, spec)
	}

	f.policy = map[string]catalog.TrustPolicy{}
	for name, raw := range c.Policies {
		var p catalog.TrustPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("policy %s: %v", name, err)
		}
		f.policy[name] = p
	}
	return f
}

func (f *fixtures) rootsFor(name string) []*x509.Certificate {
	if name == "" {
		name = "ca"
	}
	if cert, ok := f.roots[name]; ok {
		return []*x509.Certificate{cert}
	}
	return nil
}

func TestCatalogVectors(t *testing.T) {
	f := newFixtures(t)

	for _, v := range f.corpus.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			switch v.Kind {
			case "snapshot":
				runSnapshot(t, f, v)
			case "delta":
				runDelta(t, f, v)
			case "discovery":
				runDiscovery(t, f, v)
			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}

func runSnapshot(t *testing.T, f *fixtures, v vector) {
	t.Helper()
	raw := f.corpus.Catalogs[v.Catalog]
	policy := f.policy[v.Policy]
	state := f.corpus.States[v.State]

	var res catalog.Result
	var err error
	var sig []byte
	if v.Publisher != "" {
		key := fixtureKey(t, f.corpus.Publishers[v.Publisher].Seed)
		sig, err = pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs[v.Publisher], key, nil)
	}
	if err == nil {
		res, err = catalog.VerifySigned(raw, sig, f.rootsFor(v.Roots), policy, state)
	}
	checkOutcome(t, v, err, func() (int64, string) { return res.Generation, res.CatalogDigest })
}

func runDelta(t *testing.T, f *fixtures, v vector) {
	t.Helper()
	baseRaw := f.corpus.Catalogs[v.Catalog]
	base, err := catalog.ParseCatalog(baseRaw)
	if err != nil {
		t.Fatalf("base catalog: %v", err)
	}
	d, err := catalog.ParseDelta(f.corpus.Deltas[v.Delta])
	if err != nil {
		checkOutcome(t, v, err, func() (int64, string) { return 0, "" })
		return
	}
	next, err := catalog.Apply(*base, *d)
	if err != nil {
		checkOutcome(t, v, err, func() (int64, string) { return 0, "" })
		return
	}
	digest, _ := next.Digest()
	checkOutcome(t, v, nil, func() (int64, string) { return next.Generation, digest })
}

func runDiscovery(t *testing.T, f *fixtures, v vector) {
	t.Helper()
	d, err := catalog.ParseDiscovery(f.corpus.Discoveries[v.Discovery])
	if err == nil {
		base, parseErr := catalog.ParseCatalog(f.corpus.Catalogs[v.Catalog])
		if parseErr != nil {
			t.Fatalf("base catalog: %v", parseErr)
		}
		err = d.Match(*base)
	}
	checkOutcome(t, v, err, func() (int64, string) { return 0, "" })
}

func checkOutcome(t *testing.T, v vector, err error, fields func() (int64, string)) {
	t.Helper()
	if v.Expectation.OK {
		if err != nil {
			t.Fatalf("expected accept, got %v", err)
		}
		generation, digest := fields()
		if v.Expectation.Generation != 0 && generation != v.Expectation.Generation {
			t.Fatalf("generation %d, want %d", generation, v.Expectation.Generation)
		}
		if v.Expectation.Digest != "" && digest != v.Expectation.Digest {
			t.Fatalf("digest %s, want %s", digest, v.Expectation.Digest)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected %s, got accept", v.Expectation.Reason)
	}
	if got := catalog.CodeOf(err); got != v.Expectation.Reason {
		t.Fatalf("reason %q, want %q (%v)", got, v.Expectation.Reason, err)
	}
}

// ------------------------------------------------------------------ fixtures

func fixtureKey(t *testing.T, seed string) *ecdsa.PrivateKey {
	t.Helper()
	// crypto/ecdsa.GenerateKey consumes a random number of reader bytes, so a
	// deterministic reader does not produce a reproducible key; derive the
	// scalar instead.
	curve := elliptic.P256()
	n := curve.Params().N
	d := new(big.Int)
	for ctr := 0; ; ctr++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("varwof/catalog-v1/%s/%d", seed, ctr)))
		d.SetBytes(sum[:])
		if d.Sign() != 0 && d.Cmp(n) < 0 {
			break
		}
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	if x == nil {
		t.Fatalf("derive key %q: invalid scalar", seed)
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
}

func serialFor(seed string) *big.Int {
	sum := sha256.Sum256([]byte(seed))
	return new(big.Int).SetBytes(sum[:16])
}

func validity() (time.Time, time.Time) {
	return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
}

func newCA(t *testing.T, seed string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := fixtureKey(t, seed)
	notBefore, notAfter := validity()
	tmpl := &x509.Certificate{
		SerialNumber:          serialFor(seed),
		Subject:               pkix.Name{CommonName: "catalog fixture CA " + seed},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

func newPublisher(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spec publisherSpec) *x509.Certificate {
	t.Helper()
	key := fixtureKey(t, spec.Seed)
	notBefore, notAfter := validity()
	tmpl := &x509.Certificate{
		SerialNumber:          serialFor("publisher-" + spec.Seed),
		Subject:               pkix.Name{CommonName: spec.Principal},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	hasAIC := spec.HasAIC == nil || *spec.HasAIC
	if hasAIC {
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		kh := sha256.Sum256(spki)
		caps := make([]pki.Capability, 0, len(spec.Capabilities))
		for _, c := range spec.Capabilities {
			var params []byte
			if len(c.Parameters) > 0 {
				params, err = json.Marshal(c.Parameters)
				if err != nil {
					t.Fatalf("marshal capability parameters: %v", err)
				}
			}
			caps = append(caps, pki.Capability{
				SchemeId:     c.SchemeID,
				CapabilityId: c.CapabilityID,
				Parameters:   params,
			})
		}
		aic := pki.AIC{
			Version:      1,
			AgentId:      "agent:" + trimPrincipal(spec.Principal),
			PrincipalUid: pki.PrincipalUid{Realm: "varwof", Identifier: trimPrincipal(spec.Principal), KeyHash: kh[:]},
			Capabilities: caps,
			DelegationAuthorization: pki.DelegationAuthorization{
				Reason:             pki.Reason{ReasonCode: "catalog-publication", Description: "publish a capability catalog"},
				RequestedLifetime:  3600,
				Timestamp:          time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
				Nonce:              make([]byte, 32),
				SignatureAlgorithm: pki.SigAlgoToOID(x509.ECDSAWithSHA256),
				SignatureValue:     []byte{0x01},
			},
		}
		der, err := asn1.Marshal(aic)
		if err != nil {
			t.Fatalf("marshal AIC: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: pki.OIDAIC, Value: der}}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create publisher cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse publisher cert: %v", err)
	}
	return cert
}

func trimPrincipal(s string) string {
	const prefix = "principal:"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func TestDeclarationDigestMatchesFile(t *testing.T) {
	raw, err := os.ReadFile(catalogDeclarationPath(t))
	if err != nil {
		t.Fatalf("read declaration: %v", err)
	}
	var decl struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &decl); err != nil {
		t.Fatalf("parse declaration: %v", err)
	}
	if got := catalog.DigestOfDeclaration(raw); got != decl.Digest {
		t.Fatalf("declaration digest %s, file carries %s", got, decl.Digest)
	}
}
