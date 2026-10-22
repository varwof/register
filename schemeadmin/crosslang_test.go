// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/schemeadmin"
)

// The cross-language phase (§7 of the implementation brief) runs the same 26
// corpus vectors through the Go confirmation path and through the Python and
// TypeScript probes in capability/contrib/scheme-admin.  All three render the
// same evidence line, so agreement is a byte comparison, not a per-field
// comparison with its own tolerance.
//
// The bundle handed to the probes contains only *inputs*: the exact payload
// bytes, the canonical package/transition objects, the materialised trust
// policy, the local registry state and the detached PKCS#7 signature.  It
// contains no expected verdict and no Go result, so a probe cannot pass by
// echoing the reference answer.

type crossLangBundle struct {
	Version      string            `json:"@version"`
	CorpusSHA256 string            `json:"corpus_sha256"`
	Vectors      []crossLangVector `json:"vectors"`
}

type crossLangVector struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Definition  string   `json:"definition_b64"`
	Declaration string   `json:"declaration_b64"`
	Package     string   `json:"package_b64"`
	Transition  string   `json:"transition_b64"`
	Policy      string   `json:"policy_b64"`
	State       string   `json:"state_b64"`
	Delegation  string   `json:"delegation_b64,omitempty"`
	Roots       []string `json:"roots_b64,omitempty"`
	Signature   string   `json:"p7s_b64,omitempty"`
	// TransitionSignature is the detached signature over transition_b64.
	TransitionSignature string `json:"transition_p7s_b64,omitempty"`
	// DelegationSignature is the detached signature over delegation_b64.
	DelegationSignature string `json:"delegation_p7s_b64,omitempty"`
}

func TestCrossLanguageVectors(t *testing.T) {
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}

	bundle := crossLangBundle{
		Version:      "varwof/scheme-admin-crosslang-bundle-v1",
		CorpusSHA256: schemeadmin.Digest(raw),
	}
	goLines := make([]string, 0, len(c.Vectors))
	for _, v := range c.Vectors {
		bv, line := materializeForCrossLang(t, &c, v)
		bundle.Vectors = append(bundle.Vectors, bv)
		goLines = append(goLines, line)
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	encoded, err := json.MarshalIndent(bundle, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("SA_BUNDLE_OUT"); out != "" {
		if err := os.WriteFile(out, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pyProbe := probePath(t, "probe.py")
	tsProbe := probePath(t, "probe.ts")
	if pyProbe == "" || tsProbe == "" {
		t.Skipf("cross-language probes not found next to the corpus; skipping §7 evidence")
	}

	python := runProbe(t, "python3", pyProbe, bundlePath)
	node := runProbe(t, "node", "--experimental-strip-types", tsProbe, bundlePath)

	want := strings.Join(goLines, "\n")
	if out := os.Getenv("SA_GO_LINES_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(want+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, got := range map[string]string{"python": python, "typescript": node} {
		if got != want {
			t.Fatalf("%s probe disagrees with the Go confirmation path\n--- go ---\n%s\n--- %s ---\n%s",
				name, diffLines(want, got), name, diffLines(got, want))
		}
	}
	if python != node {
		t.Fatalf("python and typescript probes disagree\n--- python ---\n%s\n--- typescript ---\n%s",
			python, node)
	}

	if outDir := os.Getenv("SA_CROSSLANG_OUT"); outDir != "" {
		writeCrossLangOut(t, filepath.Join(outDir, "out-python.txt"), pyProbe, bundle.CorpusSHA256, python)
		writeCrossLangOut(t, filepath.Join(outDir, "out-typescript.txt"), tsProbe, bundle.CorpusSHA256, node)
	}

	t.Logf("cross-language: %d vectors agree across Go, Python and TypeScript (corpus %s)",
		len(c.Vectors), bundle.CorpusSHA256)
}

// materializeForCrossLang is the single-vector path.  It mirrors runVector but
// returns a renderable outcome instead of asserting.
func materializeForCrossLang(t *testing.T, c *corpus, v vectorSpec) (crossLangVector, string) {
	t.Helper()

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
	caCert, caKey := newCA(t, "ca-"+v.ID)
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
	polBytes, err := json.Marshal(pol.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}

	bv := crossLangVector{
		ID:          v.ID,
		Kind:        v.Kind,
		Definition:  b64(defBytes),
		Declaration: b64(declBytes),
		Policy:      b64(polBytes),
		Roots:       []string{b64(caCert.Raw)},
	}

	out := outcome{verdict: schemeadmin.VerdictReject}

	if v.Kind == "delegation" {
		if v.Delegation == nil {
			t.Fatalf("%s: delegation vector without a delegation object", v.ID)
		}
		delBytes, err := json.Marshal(v.Delegation)
		if err != nil {
			t.Fatal(err)
		}
		bv.Delegation = b64(delBytes)
		delSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, delBytes, pubCert, pubKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		bv.DelegationSignature = b64(delSig)
		err = schemeadmin.ValidateSignedDelegation(delBytes, delSig, []*x509.Certificate{caCert}, pol.TrustPolicy)
		out.verdict = verdictOf(err)
		out.reason = schemeadmin.CodeOf(err)
		return bv, renderOutcome(v.ID, v.Kind, out)
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

	var stBytes []byte
	if len(v.State) > 0 {
		stRaw, err := resolveRef(v.State, c.States)
		if err != nil {
			t.Fatal(err)
		}
		stBytes = stRaw
	} else {
		stBytes = []byte("{}")
	}

	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("build PKCS#7: %v", err)
	}
	trSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("build transition PKCS#7: %v", err)
	}

	bv.Package = b64(pkgBytes)
	bv.Transition = b64(trBytes)
	bv.Signature = b64(sig)
	bv.TransitionSignature = b64(trSig)

	var st schemeadmin.RegistryState
	if err := json.Unmarshal(stBytes, &st); err != nil {
		t.Fatalf("state: %v", err)
	}
	hydrateRevocations(t, &st, pubCert, pubKey, caCert)
	if stBytes, err = json.Marshal(st); err != nil {
		t.Fatalf("state: %v", err)
	}
	bv.State = b64(stBytes)
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
	out.verdict = res.Verdict
	out.reason = res.Reason
	out.pkg = res.PackageDigest
	out.tr = res.TransitionDigest
	out.op = res.ManagementOperationDigest
	out.key = res.PublisherKeyID
	return bv, renderOutcome(v.ID, v.Kind, out)
}

type outcome struct {
	verdict, reason  string
	pkg, tr, op, key string
	line             string
}

func verdictOf(err error) string {
	if err != nil {
		return schemeadmin.VerdictReject
	}
	return schemeadmin.VerdictAccept
}

// renderOutcome is the shared evidence line format.  It is deliberately
// positional and stable; a semantic difference changes the line, not just an
// exit code.
func renderOutcome(id, kind string, o outcome) string {
	reason := o.reason
	if reason == "" {
		reason = "-"
	}
	parts := []string{id, kind, o.verdict, reason}
	for _, f := range [][2]string{
		{"pkg", o.pkg},
		{"tr", o.tr},
		{"op", o.op},
		{"key", o.key},
	} {
		if f[1] != "" {
			parts = append(parts, f[0]+"="+f[1])
		}
	}
	return strings.Join(parts, " ")
}

func b64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// probePath locates capability/contrib/scheme-admin from either test working
// directory.
func probePath(t *testing.T, name string) string {
	t.Helper()
	candidates := []string{
		"../capability/contrib/scheme-admin/" + name,
		"../../capability/contrib/scheme-admin/" + name,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runProbe(t *testing.T, name string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed; skipping cross-language evidence", name)
	}
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.String())
	}
	return strings.TrimRight(stdout.String(), "\n")
}

func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			b.WriteString("- " + wl + "\n+ " + gl + "\n")
		}
	}
	return b.String()
}

func writeCrossLangOut(t *testing.T, path, probe, corpusSHA, body string) {
	t.Helper()
	probeRaw, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	header := strings.Join([]string{
		"# varwof/scheme-admin-v1 cross-language evidence",
		"# corpus_sha256: " + corpusSHA,
		"# probe: " + filepath.Base(probe),
		"# probe_sha256: " + schemeadmin.Digest(probeRaw),
		"",
	}, "\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(header+body+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
