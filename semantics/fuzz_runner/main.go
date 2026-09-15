// CLC differential fuzz: Go runner.
//
// Reads the generator's JSONL and, for every case, evaluates BOTH paths with
// the *Go* implementation, mirroring fuzz/run_py.py and fuzz/run_ts.ts:
//   - raw_path:     §6.2 raw-text normalization via ValidateRawParams, then
//                   encoding/json decode and Authorize.
//   - decoded_path: skip raw-text validation; decode with encoding/json
//                   directly (Go's decoder drops duplicate keys, silently
//                   replaces lone surrogates with U+FFFD, and rejects huge
//                   numbers like 1e400).
//   - canonical_sha256: sha256 of CanonicalJSON bytes over the decoded params
//                   value; "" when no value is producible.
//
// Emits result JSONL:
//   {"id":..., "impl":"go", "raw_path":{...}, "decoded_path":{...},
//    "canonical_sha256":"..."}
// A panic is recovered per case and emitted as {"id":..., "impl":"go",
//   "error":"..."}.
//
// Usage: go run ./semantics/fuzz_runner <cases.jsonl>

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/semantics"
)

// canonicalReason returns the stable reason code: everything before the first
// ':' (CLC-v1 §9.4: codes are prefixes; ": <detail>" is diagnostic).
func canonicalReason(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

type result struct {
	ID      string      `json:"id"`
	Impl    string      `json:"impl"`
	RawPath *pathResult `json:"raw_path,omitempty"`
	DecPath *pathResult `json:"decoded_path,omitempty"`
	Sha     string      `json:"canonical_sha256,omitempty"`
	Err     string      `json:"error,omitempty"`
}

type pathResult struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

type fuzzCase struct {
	ID      string          `json:"id"`
	Axis    string          `json:"axis"`
	Raw     string          `json:"raw"`
	OpID    string          `json:"op_id"`
	Grant   semantics.Grant `json:"grant"`
	NoParam bool            `json:"no_params"`
	RawB64  string          `json:"raw_b64"`
	Note    string          `json:"note"`
}

func authorize(grant semantics.Grant, op semantics.Operation) (v string, r string, ok bool) {
	defer func() {
		if p := recover(); p != nil {
			v, r, ok = "deny", fmt.Sprintf("panic:%v", p), false
		}
	}()
	d := semantics.Authorize(grant, op)
	return d.Verdict, canonicalReason(d.Reason), true
}

func rawPath(c fuzzCase) *pathResult {
	if c.NoParam {
		v, r, _ := authorize(c.Grant, semantics.Operation{ID: c.OpID})
		return &pathResult{v, r}
	}
	if err := semantics.ValidateRawParams(c.Raw); err != nil {
		return &pathResult{"deny", canonicalReason(err.Error())}
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(c.Raw), &params); err != nil {
		return &pathResult{"deny", "invalid_params_number"}
	}
	v, r, _ := authorize(c.Grant, semantics.Operation{ID: c.OpID, Params: params})
	return &pathResult{v, r}
}

func decodedPath(c fuzzCase) (*pathResult, map[string]any, bool) {
	if c.NoParam {
		v, r, _ := authorize(c.Grant, semantics.Operation{ID: c.OpID})
		return &pathResult{v, r}, nil, true
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(c.Raw), &params); err != nil {
		return &pathResult{"deny", "invalid_params_number"}, nil, false
	}
	v, r, _ := authorize(c.Grant, semantics.Operation{ID: c.OpID, Params: params})
	return &pathResult{v, r}, params, true
}

func canonicalSha(params map[string]any, decOk bool, noParam bool) string {
	// Value-layer digest is only defined over a successfully decoded object
	// param set (§6.2 params must be an object).  For no_params operations the
	// value layer is the canonical null (sha256("null")), matching py/ts.
	if !decOk && !noParam {
		return ""
	}
	cb, err := semantics.CanonicalJSON(params)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cb)
	return fmt.Sprintf("%x", sum)
}

func evalCase(c fuzzCase) (res result) {
	res = result{ID: c.ID, Impl: "go"}
	defer func() {
		if p := recover(); p != nil {
			res = result{ID: c.ID, Impl: "go", Err: fmt.Sprintf("%v", p)}
		}
	}()
	var dps map[string]any
	decOk := false
	res.RawPath = rawPath(c)
	res.DecPath, dps, decOk = decodedPath(c)
	res.Sha = canonicalSha(dps, decOk, c.NoParam)
	return res
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fuzz_runner <cases.jsonl>")
		os.Exit(2)
	}
	fh, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer fh.Close()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c fuzzCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			var id string
			var probe struct {
				ID string `json:"id"`
			}
			if json.Unmarshal([]byte(line), &probe) == nil {
				id = probe.ID
			}
			enc.Encode(result{ID: id, Impl: "go", Err: "bad-case-line: " + err.Error()})
			continue
		}
		if c.RawB64 != "" && c.Raw == "" {
			b, err := base64.StdEncoding.DecodeString(c.RawB64)
			if err == nil {
				c.Raw = string(b)
			}
		}
		enc.Encode(evalCase(c))
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
