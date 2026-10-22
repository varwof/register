// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin_test

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/varwof/pkcs7"
	pki "github.com/varwof/types"

	"github.com/varwof/register/schemeadmin"
)

// ------------------------------------------------------------------ corpus IO

type corpus struct {
	Definitions  map[string]json.RawMessage `json:"definitions"`
	Declarations map[string]json.RawMessage `json:"declarations"`
	Publishers   map[string]publisherSpec   `json:"publishers"`
	Policies     map[string]json.RawMessage `json:"policies"`
	States       map[string]json.RawMessage `json:"states"`
	Vectors      []vectorSpec               `json:"vectors"`
}

type publisherSpec struct {
	Seed         string    `json:"seed"`
	Principal    string    `json:"principal"`
	HasAIC       *bool     `json:"has_aic"`
	Capabilities []capSpec `json:"capabilities"`
}

type capSpec struct {
	SchemeID     string         `json:"scheme_id"`
	CapabilityID string         `json:"capability_id"`
	Parameters   map[string]any `json:"parameters,omitempty"`
}

type vectorSpec struct {
	ID          string                  `json:"id"`
	Kind        string                  `json:"kind"`
	SpecClause  string                  `json:"spec_clause"`
	Derivation  string                  `json:"derivation"`
	Definition  string                  `json:"definition"`
	Declaration string                  `json:"declaration"`
	Publisher   string                  `json:"publisher"`
	Policy      json.RawMessage         `json:"policy"`
	State       json.RawMessage         `json:"state"`
	Package     json.RawMessage         `json:"package"`
	Transition  json.RawMessage         `json:"transition"`
	Delegation  *schemeadmin.Delegation `json:"delegation"`
	Expect      struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	} `json:"expect"`
}

type policySpec struct {
	schemeadmin.TrustPolicy
	RootKeySeeds     []string `json:"root_key_seeds"`
	NextRootKeySeeds []string `json:"next_root_key_seeds"`
}

func corpusPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../capability/data/_vectors/scheme-admin-v1/scheme-admin-vectors.json",
		"../../capability/data/_vectors/scheme-admin-v1/scheme-admin-vectors.json",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("scheme-admin corpus not found in %v (capability checkout absent); skipping", candidates)
	return ""
}

// TestSchemeAdminVectors runs every corpus vector through the same path the
// deployer CLI uses: closed parse, detached PKCS#7 verification, then Confirm.
func TestSchemeAdminVectors(t *testing.T) {
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Vectors) < 22 {
		t.Fatalf("corpus has %d vectors, want at least 22", len(c.Vectors))
	}
	for _, v := range c.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			runVector(t, &c, v)
		})
	}
}

// hydrateRevocations gives static corpus states a signed tombstone over the
// revocation metadata.  Product code refuses unsigned revocation records.
func hydrateRevocations(t *testing.T, st *schemeadmin.RegistryState, pubCert *x509.Certificate, pubKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	for i := range st.Revoked {
		r := &st.Revoked[i]
		if len(r.Tombstone) > 0 {
			continue
		}
		generation := r.Generation
		if generation <= 0 {
			generation = st.Generation + 1
			r.Generation = generation
		}
		fromGeneration := st.Generation
		tombstoneGeneration := generation
		toDigest := r.ReplacementDigest
		if toDigest == "" {
			toDigest = schemeadmin.Digest([]byte("tombstone:" + r.PackageDigest))
		}
		tr := schemeadmin.Transition{
			Version:                 schemeadmin.TransitionVersion,
			Action:                  schemeadmin.ActionRevoke,
			Scheme:                  st.Scheme,
			Namespace:               "/" + st.Scheme,
			FromGeneration:          &fromGeneration,
			ToGeneration:            generation,
			FromDigest:              r.PackageDigest,
			ToDigest:                toDigest,
			ChangeClass:             schemeadmin.ChangePatch,
			TargetCLCRevision:       "CLC-1.19",
			RevocationReason:        r.Reason,
			RevocationEffectiveTime: r.EffectiveTime,
			ReplacementDigest:       r.ReplacementDigest,
			TombstoneGeneration:     &tombstoneGeneration,
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, pubCert, pubKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		r.Tombstone = raw
		r.Signature = sig
	}
}

func runVector(t *testing.T, c *corpus, v vectorSpec) {
	t.Helper()

	caCert, caKey := newCA(t, "ca-"+v.ID)

	defRaw, ok := c.Definitions[v.Definition]
	if !ok {
		t.Fatalf("unknown definition fixture %q", v.Definition)
	}
	declRaw, ok := c.Declarations[v.Declaration]
	if !ok {
		t.Fatalf("unknown declaration fixture %q", v.Declaration)
	}
	defBytes := mustCanonical(t, mustMap(t, defRaw))
	declBytes := mustCanonical(t, mustMap(t, declRaw))

	pub, ok := c.Publishers[v.Publisher]
	if !ok {
		t.Fatalf("unknown publisher fixture %q", v.Publisher)
	}
	pubCert, pubKey := newPublisher(t, caCert, caKey, pub)

	polRaw, err := resolveRef(v.Policy, c.Policies)
	if err != nil {
		t.Fatal(err)
	}
	var pol policySpec
	if err := json.Unmarshal(polRaw, &pol); err != nil {
		t.Fatalf("policy: %v", err)
	}
	pol.RootKeys = keyIDs(t, caCert, caKey, pol.RootKeySeeds)
	pol.NextRootKeys = keyIDs(t, caCert, caKey, pol.NextRootKeySeeds)

	if v.Kind == "delegation" {
		delBytes, err := json.Marshal(v.Delegation)
		if err != nil {
			t.Fatal(err)
		}
		delSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, delBytes, pubCert, pubKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatalf("build delegation signature: %v", err)
		}
		err = schemeadmin.ValidateSignedDelegation(delBytes, delSig, []*x509.Certificate{caCert}, pol.TrustPolicy)
		checkOutcome(t, v, "", err)
		return
	}

	pkgMap := mustMap(t, v.Package)
	if _, ok := pkgMap["definition_digest"]; !ok {
		pkgMap["definition_digest"] = schemeadmin.Digest(defBytes)
	}
	if _, ok := pkgMap["declaration_digest"]; !ok {
		pkgMap["declaration_digest"] = schemeadmin.Digest(declBytes)
	}
	pkgBytes := mustCanonical(t, pkgMap)

	trMap := mustMap(t, v.Transition)
	if seeds, ok := trMap["next_root_key_seeds"]; ok {
		var names []string
		for _, s := range seeds.([]any) {
			names = append(names, s.(string))
		}
		trMap["next_root_keys"] = keyIDs(t, caCert, caKey, names)
		delete(trMap, "next_root_key_seeds")
	}
	if _, ok := trMap["to_digest"]; !ok {
		trMap["to_digest"] = schemeadmin.Digest(pkgBytes)
	}
	trBytes := mustCanonical(t, trMap)

	var st schemeadmin.RegistryState
	if len(v.State) > 0 {
		stRaw, err := resolveRef(v.State, c.States)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(stRaw, &st); err != nil {
			t.Fatalf("state: %v", err)
		}
	}
	hydrateRevocations(t, &st, pubCert, pubKey, caCert)

	// The deployer verifies both detached signatures over the exact bytes.
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("build PKCS#7: %v", err)
	}
	trSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("build transition PKCS#7: %v", err)
	}

	res, err := schemeadmin.ConfirmSigned(schemeadmin.SignedConfirmation{
		PackageBytes:         pkgBytes,
		Signatures:           [][]byte{sig},
		TransitionBytes:      trBytes,
		TransitionSignatures: [][]byte{trSig},
		Definition:           defBytes,
		Declaration:          declBytes,
		Roots:                []*x509.Certificate{caCert},
		State:                st,
		Policy:               pol.TrustPolicy,
	})
	if !checkOutcome(t, v, res.Verdict, err) {
		return
	}
	if res.Verdict != schemeadmin.VerdictAccept {
		t.Fatalf("expected verdict accept, got %q", res.Verdict)
	}
	for name, got := range map[string]string{
		"package digest":      res.PackageDigest,
		"transition digest":   res.TransitionDigest,
		"operation digest":    res.ManagementOperationDigest,
		"certificate digest":  res.PublisherCertificateDigest,
		"trust policy digest": res.TrustPolicyDigest,
		"inputs digest":       res.InputsDigest,
	} {
		if got == "" {
			t.Errorf("accepted result is missing %s", name)
		}
	}
}

// checkOutcome asserts the vector's expectation.  It returns true when the
// vector expected and received an accept.
func checkOutcome(t *testing.T, v vectorSpec, verdict string, err error) bool {
	t.Helper()
	code := schemeadmin.CodeOf(err)
	if v.Expect.OK {
		if err != nil {
			t.Fatalf("expected accept, got %s (%v)", code, err)
		}
		return true
	}
	if err == nil {
		t.Fatalf("expected reject %q, got verdict %q", v.Expect.Reason, verdict)
	}
	if code != v.Expect.Reason {
		t.Fatalf("expected reject %q, got %q (%v)", v.Expect.Reason, code, err)
	}
	return false
}

func resolveRef(raw json.RawMessage, table map[string]json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		v, ok := table[name]
		if !ok {
			return nil, fmt.Errorf("unknown fixture %q", name)
		}
		return v, nil
	}
	return raw, nil
}

func mustMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	return m
}

// mustCanonical is the corpus's payload encoding: compact JSON with sorted keys,
// no HTML escaping.  It is RFC 8785 for these ASCII objects and is what the
// generator hashes.
func mustCanonical(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("canonical encode: %v", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// ------------------------------------------------------- deterministic keys

func fixtureKey(t *testing.T, seed string) *ecdsa.PrivateKey {
	t.Helper()
	// Derive the scalar directly.  crypto/ecdsa.GenerateKey deliberately
	// consumes a random number of reader bytes (randutil.MaybeReadByte), so a
	// deterministic io.Reader does not make it reproducible.
	curve := elliptic.P256()
	n := curve.Params().N
	d := new(big.Int)
	for ctr := 0; ; ctr++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("varwof/scheme-admin-v1/%s/%d", seed, ctr)))
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
	return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
}

func newCA(t *testing.T, seed string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := fixtureKey(t, seed)
	notBefore, notAfter := validity()
	tmpl := &x509.Certificate{
		SerialNumber:          serialFor(seed),
		Subject:               pkix.Name{CommonName: "scheme-admin fixture CA " + seed},
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

// newPublisher issues a publisher certificate under ca.  When has_aic is true it
// carries an AIC whose principal key hash binds the certificate key.
func newPublisher(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spec publisherSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
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
		keyHash := sha256.Sum256(spki)
		aic := pki.AIC{
			Version:      1,
			AgentId:      "agent:" + trimPrincipal(spec.Principal),
			PrincipalUid: pki.PrincipalUid{Realm: "varwof", Identifier: trimPrincipal(spec.Principal), KeyHash: keyHash[:]},
			Capabilities: caps,
			DelegationAuthorization: pki.DelegationAuthorization{
				Reason:             pki.Reason{ReasonCode: "scheme-publication", Description: "publish a scheme package"},
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
	return cert, key
}

// keyIDs materialises fixture keys and returns their `sha256:` key ids.
func keyIDs(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, seeds []string) []string {
	t.Helper()
	out := make([]string, 0, len(seeds))
	for _, s := range seeds {
		cert, _ := newPublisher(t, caCert, caKey, publisherSpec{Seed: s, Principal: "principal:root-admin"})
		out = append(out, schemeadmin.KeyID(cert))
	}
	return out
}

func trimPrincipal(p string) string {
	const prefix = "principal:"
	if len(p) > len(prefix) && p[:len(prefix)] == prefix {
		return p[len(prefix):]
	}
	return p
}
