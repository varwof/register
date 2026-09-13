// Command record turns a CLC decision into a Decision Record, and checks one
// back.  It is the runnable face of the evidence step: `record` freezes the
// inputs and the verdict together, `record -verify` re-runs the language over a
// record a holder did not produce.
//
//	go run ./cmd/record input.json              # bare Decision Record
//	go run ./cmd/record -envelope input.json    # DSSE/in-toto envelope around it
//	go run ./cmd/record -verify record.json     # accepts either container
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/varwof/register/semantics"
)

// Input is the decision to record: a grant set and the operation it is
// evaluated against.
type Input struct {
	Grants    []semantics.Grant   `json:"grants"`
	Operation semantics.Operation `json:"operation"`
}

func main() {
	verify := flag.Bool("verify", false, "read a Decision Record (or its envelope) and re-run the language to verify it")
	envelope := flag.Bool("envelope", false, "emit a DSSE envelope whose in-toto statement carries the record as its predicate")
	compact := flag.Bool("compact", false, "emit canonical (single-line) JSON instead of indented")
	flag.Parse()

	raw, err := readInput(flag.Args())
	if err != nil {
		fail(err)
	}

	if *verify {
		rec, err := decodeAny(raw)
		if err != nil {
			fail(err)
		}
		if err := rec.Verify(); err != nil {
			fail(err)
		}
		fmt.Printf("ok %s sha-256:%x\n", rec.Verdict, rec.InputDigest.Value)
		return
	}

	in, err := decodeInput(raw)
	if err != nil {
		fail(err)
	}
	rec, err := semantics.Record(in.Grants, in.Operation)
	if err != nil {
		fail(err)
	}

	var out []byte
	if *envelope {
		env, err := semantics.NewEnvelope(rec)
		if err != nil {
			fail(err)
		}
		if err := env.Check(); err != nil {
			fail(err)
		}
		if out, err = json.Marshal(env); err != nil {
			fail(err)
		}
	} else if out, err = rec.CanonicalBytes(); err != nil {
		fail(err)
	}
	if !*compact {
		// Indent the canonical bytes in place: re-encoding through a map
		// would reorder the record's fields.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, out, "", "  "); err == nil {
			out = pretty.Bytes()
		}
	}
	os.Stdout.Write(out)
	fmt.Println()
}

func decodeInput(raw []byte) (Input, error) {
	if looksLikeRecord(raw) || looksLikeEnvelope(raw) {
		return Input{}, fmt.Errorf("input looks like a Decision Record or envelope; pass -verify to check it")
	}
	var in Input
	err := json.Unmarshal(raw, &in)
	return in, err
}

func decodeRecord(raw []byte) (semantics.DecisionRecord, error) {
	var rec semantics.DecisionRecord
	err := json.Unmarshal(raw, &rec)
	return rec, err
}

// decodeAny accepts either container: a bare Decision Record, or a DSSE
// envelope whose in-toto statement carries the record.  Envelopes are checked
// structurally (payload type, statement shape, subject binding) — signature
// verification needs keys and belongs to the caller.
func decodeAny(raw []byte) (semantics.DecisionRecord, error) {
	if looksLikeEnvelope(raw) {
		var env semantics.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return semantics.DecisionRecord{}, err
		}
		rec, err := env.DecisionRecord()
		if err != nil {
			return semantics.DecisionRecord{}, err
		}
		if err := env.Check(); err != nil {
			return semantics.DecisionRecord{}, err
		}
		if len(env.Signatures) > 0 {
			fmt.Fprintf(os.Stderr, "record: envelope carries %d signature(s); structural check only, no keys available\n", len(env.Signatures))
		}
		return rec, nil
	}
	return decodeRecord(raw)
}

// looksLikeEnvelope distinguishes the DSSE container by its defining members.
func looksLikeEnvelope(raw []byte) bool {
	var probe struct {
		PayloadType *string `json:"payloadType"`
		Payload     *string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.PayloadType != nil && probe.Payload != nil
}

// looksLikeRecord distinguishes the two shapes by the fields only a record
// carries; it never guesses on ambiguous input.
func looksLikeRecord(raw []byte) bool {
	var probe struct {
		Lang        *string `json:"lang"`
		InputDigest any     `json:"input_digest"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Lang != nil && probe.InputDigest != nil
}

func readInput(args []string) ([]byte, error) {
	if len(args) == 0 {
		return io.ReadAll(os.Stdin)
	}
	if len(args) > 1 {
		return nil, fmt.Errorf("expected at most one input file, got %d", len(args))
	}
	return os.ReadFile(args[0])
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "record:", err)
	os.Exit(1)
}
