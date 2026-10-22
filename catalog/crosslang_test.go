// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/catalog"
)

// TestCrossLanguageVectors runs the same catalog corpus through the Go
// implementation and through the Python and TypeScript probes in
// capability/contrib/catalog.  All three render the same positional evidence
// line, so agreement is a byte comparison.
//
// The bundle carries inputs only: exact artifact bytes, the deployer policy,
// the accepted-generation state, the trusted root, the signer certificate and
// the detached PKCS#7 signature.  It carries no expected verdict and no Go
// result, so a probe cannot pass by echoing the reference answer.
type catalogBundle struct {
	Version      string                `json:"@version"`
	CorpusSHA256 string                `json:"corpus_sha256"`
	Vectors      []catalogBundleVector `json:"vectors"`
}

type catalogBundleVector struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Catalog    string   `json:"catalog_b64,omitempty"`
	Delta      string   `json:"delta_b64,omitempty"`
	Discovery  string   `json:"discovery_b64,omitempty"`
	Policy     string   `json:"policy_b64,omitempty"`
	State      string   `json:"state_b64,omitempty"`
	Roots      []string `json:"roots_b64,omitempty"`
	SignerCert string   `json:"signer_cert_b64,omitempty"`
	Signature  string   `json:"signature_b64,omitempty"`
}

func TestCrossLanguageVectors(t *testing.T) {
	f := newFixtures(t)

	bundle := catalogBundle{
		Version:      "varwof/catalog-crosslang-bundle-v1",
		CorpusSHA256: catalog.Digest(mustRead(t, catalogVectorPath(t))),
	}
	goLines := make([]string, 0, len(f.corpus.Vectors))
	for _, v := range f.corpus.Vectors {
		bv, line := materializeCatalogVector(t, f, v)
		bundle.Vectors = append(bundle.Vectors, bv)
		goLines = append(goLines, line)
	}

	dir := t.TempDir()
	encoded, err := json.MarshalIndent(bundle, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("CAT_BUNDLE_OUT"); out != "" {
		if err := os.WriteFile(out, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pyProbe := probePath(t, "probe.py")
	tsProbe := probePath(t, "probe.ts")
	if pyProbe == "" || tsProbe == "" {
		t.Skipf("cross-language probes not found next to the corpus; skipping catalog evidence")
	}

	python := runProbe(t, "python3", pyProbe, bundlePath)
	node := runProbe(t, "node", "--experimental-strip-types", tsProbe, bundlePath)

	want := strings.Join(goLines, "\n")
	if out := os.Getenv("CAT_GO_LINES_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(want+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if python != want {
		t.Fatalf("python probe disagrees with Go\n--- go ---\n%s\n--- python ---\n%s",
			diffLines(want, python), diffLines(python, want))
	}
	if node != want {
		t.Fatalf("typescript probe disagrees with Go\n--- go ---\n%s\n--- typescript ---\n%s",
			diffLines(want, node), diffLines(node, want))
	}

	if outDir := os.Getenv("CAT_CROSSLANG_OUT"); outDir != "" {
		writeProbeOut(t, filepath.Join(outDir, "out-python.txt"), "probe.py", bundle.CorpusSHA256, python)
		writeProbeOut(t, filepath.Join(outDir, "out-typescript.txt"), "probe.ts", bundle.CorpusSHA256, node)
	}

	t.Logf("catalog cross-language: %d vectors agree across Go, Python and TypeScript (corpus %s)",
		len(f.corpus.Vectors), bundle.CorpusSHA256)
}

func materializeCatalogVector(t *testing.T, f *fixtures, v vector) (catalogBundleVector, string) {
	t.Helper()
	bv := catalogBundleVector{ID: v.ID, Kind: v.Kind}

	switch v.Kind {
	case "snapshot":
		raw := f.corpus.Catalogs[v.Catalog]
		bv.Catalog = b64(raw)
		if v.Publisher != "" {
			cert := f.certs[v.Publisher]
			spec := f.corpus.Publishers[v.Publisher]
			key := fixtureKey(t, spec.Seed)
			sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, cert, key, nil)
			if err != nil {
				t.Fatalf("%s: sign: %v", v.ID, err)
			}
			bv.SignerCert = b64(cert.Raw)
			bv.Signature = b64(sig)
		}
		bv.Policy = b64(mustRead(t, policyPath(t, f, v.Policy)))
		bv.State = b64(mustJSON(t, f.corpus.States[v.State]))
		for _, root := range f.rootsFor(v.Roots) {
			bv.Roots = append(bv.Roots, b64(root.Raw))
		}
		return bv, runGoSnapshotLine(t, f, v)

	case "delta":
		bv.Catalog = b64(f.corpus.Catalogs[v.Catalog])
		bv.Delta = b64(f.corpus.Deltas[v.Delta])
		return bv, runGoDeltaLine(t, f, v)

	case "discovery":
		bv.Catalog = b64(f.corpus.Catalogs[v.Catalog])
		bv.Discovery = b64(f.corpus.Discoveries[v.Discovery])
		return bv, runGoDiscoveryLine(t, f, v)

	default:
		t.Fatalf("%s: unknown kind %q", v.ID, v.Kind)
		return bv, ""
	}
}

func runGoSnapshotLine(t *testing.T, f *fixtures, v vector) string {
	t.Helper()
	out := outcome{id: v.ID, kind: v.Kind}
	raw := f.corpus.Catalogs[v.Catalog]
	cat, err := catalog.ParseCatalog(raw)
	if err == nil {
		out.digest, _ = cat.Digest()
		out.generation = cat.Generation
		var sig []byte
		var sigErr error
		if v.Publisher != "" {
			key := fixtureKey(t, f.corpus.Publishers[v.Publisher].Seed)
			sig, sigErr = pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs[v.Publisher], key, nil)
		} else {
			// materializeCatalogVector leaves Signature empty for the
			// signature_missing vector.
			sig = nil
		}
		if sigErr != nil {
			err = sigErr
		} else {
			res, verifyErr := catalog.VerifySigned(raw, sig, f.rootsFor(v.Roots), f.policy[v.Policy], f.corpus.States[v.State])
			out.verdict = res.Verdict
			out.reason = res.Reason
			out.key = res.SignerKeyID
			err = verifyErr
		}
	} else {
		out.verdict = catalog.VerdictReject
	}
	if err != nil {
		out.verdict = catalog.VerdictReject
		if out.reason == "" {
			out.reason = catalog.CodeOf(err)
		}
	}
	return out.render()
}

func runGoDeltaLine(t *testing.T, f *fixtures, v vector) string {
	t.Helper()
	out := outcome{id: v.ID, kind: v.Kind, verdict: catalog.VerdictAccept}
	base, err := catalog.ParseCatalog(f.corpus.Catalogs[v.Catalog])
	if err == nil {
		var d *catalog.Delta
		d, err = catalog.ParseDelta(f.corpus.Deltas[v.Delta])
		if err == nil {
			var next *catalog.Catalog
			next, err = catalog.Apply(*base, *d)
			if err == nil {
				out.generation = next.Generation
				out.digest, _ = next.Digest()
			}
		}
	}
	if err != nil {
		out.verdict = catalog.VerdictReject
		out.reason = catalog.CodeOf(err)
		out.digest, out.generation = "", 0
	}
	return out.render()
}

func runGoDiscoveryLine(t *testing.T, f *fixtures, v vector) string {
	t.Helper()
	out := outcome{id: v.ID, kind: v.Kind, verdict: catalog.VerdictAccept}
	d, err := catalog.ParseDiscovery(f.corpus.Discoveries[v.Discovery])
	if err == nil {
		var cat *catalog.Catalog
		cat, err = catalog.ParseCatalog(f.corpus.Catalogs[v.Catalog])
		if err == nil {
			err = d.Match(*cat)
			if err == nil {
				out.digest, _ = cat.Digest()
				out.generation = cat.Generation
			}
		}
	}
	if err != nil {
		out.verdict = catalog.VerdictReject
		out.reason = catalog.CodeOf(err)
		out.digest, out.generation = "", 0
	}
	return out.render()
}

type outcome struct {
	id, kind        string
	verdict, reason string
	digest, key     string
	generation      int64
}

// render is the shared evidence line.  Positional and stable: a semantic
// difference changes the line, not only an exit code.
func (o outcome) render() string {
	reason := o.reason
	if reason == "" {
		reason = "-"
	}
	parts := []string{o.id, o.kind, o.verdict, reason}
	if o.digest != "" {
		parts = append(parts, "cat="+o.digest)
	}
	if o.key != "" {
		parts = append(parts, "key="+o.key)
	}
	if o.generation != 0 {
		parts = append(parts, fmt.Sprintf("gen=%d", o.generation))
	}
	return strings.Join(parts, " ")
}

func policyPath(t *testing.T, f *fixtures, name string) string {
	t.Helper()
	raw, ok := f.corpus.Policies[name]
	if !ok {
		t.Fatalf("unknown policy %q", name)
	}
	return writeTemp(t, "policy-"+name+".json", raw)
}

func writeTemp(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func probePath(t *testing.T, name string) string {
	t.Helper()
	for _, p := range []string{
		"../capability/contrib/catalog/" + name,
		"../../capability/contrib/catalog/" + name,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runProbe(t *testing.T, name string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available", name)
	}
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", name, err, stderr.String())
	}
	return strings.TrimSuffix(string(out), "\n")
}

func diffLines(a, other string) string {
	al := strings.Split(a, "\n")
	bl := strings.Split(other, "\n")
	var sb strings.Builder
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			fmt.Fprintf(&sb, "line %d:\n  - %s\n  + %s\n", i+1, x, y)
		}
	}
	return sb.String()
}

func writeProbeOut(t *testing.T, path, probe, corpus string, lines string) {
	t.Helper()
	header := fmt.Sprintf("# generated by register/catalog TestCrossLanguageVectors\n# probe: contrib/catalog/%s\n# corpus: %s\n", probe, corpus)
	body := header + lines + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
