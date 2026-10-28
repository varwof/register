// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command scheme-admin is the deployer-side confirmation path for
// varwof/scheme-admin-v1.  It reads immutable artifacts, verifies the detached
// PKCS#7 signature over the exact package bytes, and recomputes authority
// locally.  It never trusts a member of an artifact that claims a result.
//
// Usage:
//
//	scheme-admin check        --package P --transition T [--definition D] [--declaration C]
//	                          --signature S --transition-signature TS --trust ROOTS --policy P.json
//	                          [--state S.json] [--state-out S2.json]
//	                          (repeat --signature for a root threshold)
//	scheme-admin root-rotate  ...  (the same inputs; the transition action must be root-rotate)
//	scheme-admin delegation   --delegation D.json --declaration C --signature D.p7s --trust roots.pem [--policy P.json]
//	scheme-admin operation    --package P --transition T
//	scheme-admin keyid        --cert CERT.pem
//
// Exit status: 0 accept, 2 reject, 1 usage or I/O failure.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/varwof/register"
	"github.com/varwof/register/catalog"
	"github.com/varwof/register/schemeadmin"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	var accepted bool
	switch os.Args[1] {
	case "check":
		accepted, err = runConfirm(os.Args[2:], "")
	case "root-rotate":
		accepted, err = runConfirm(os.Args[2:], schemeadmin.ActionRootRotate)
	case "delegation":
		accepted, err = runDelegation(os.Args[2:])
	case "operation":
		err = runOperation(os.Args[2:])
		accepted = true
	case "keyid":
		err = runKeyID(os.Args[2:])
		accepted = true
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "scheme-admin: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "scheme-admin: %v\n", err)
		if accepted {
			os.Exit(1)
		}
		os.Exit(2)
	}
	if !accepted {
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `scheme-admin — authority-bounded scheme publication

  check        confirm a create/update/revoke package transition
  root-rotate  confirm a root rotation (transition action must be root-rotate)
  delegation   validate a proposed sub-grant
  operation    print the management operation a deployer would authorize
  keyid        print the sha256: key id of a certificate

Accepting requires: package and transition shape, content digests, publisher
chain and AIC binding, CLC containment and decision, namespace and major limits,
registry generation, revocation, freshness and approvals.
`)
}

type commonFlags struct {
	pkgPath      string
	trPath       string
	defPath      string
	declPath     string
	sigPaths     []string
	trSigPaths   []string
	trustPath    string
	policyPath   string
	statePath    string
	stateOut     string
	declOnlyPath string
	allowStale   bool
}

func addCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.pkgPath, "package", "", "scheme package JSON")
	fs.StringVar(&c.trPath, "transition", "", "scheme transition JSON")
	fs.StringVar(&c.defPath, "definition", "", "scheme definition payload")
	fs.StringVar(&c.declPath, "declaration", "", "CLC-SCHEME-v1 declaration payload")
	fs.Func("signature", "detached PKCS#7 package signature (PEM); repeat for a root threshold", func(v string) error {
		c.sigPaths = append(c.sigPaths, v)
		return nil
	})
	fs.Func("transition-signature", "detached PKCS#7 transition signature (PEM); repeatable", func(v string) error {
		c.trSigPaths = append(c.trSigPaths, v)
		return nil
	})
	fs.StringVar(&c.trustPath, "trust", "", "trust anchor PEM bundle")
	fs.StringVar(&c.policyPath, "policy", "", "deployer trust policy JSON")
	fs.StringVar(&c.statePath, "state", "", "local registry state JSON (optional)")
	fs.StringVar(&c.stateOut, "state-out", "", "write the accepted registry state here (optional)")
	fs.BoolVar(&c.allowStale, "allow-stale-clock", false, "accept a policy observed_at far from the wall clock (offline replay)")
}

func runConfirm(args []string, wantAction string) (bool, error) {
	var c commonFlags
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	addCommon(fs, &c)
	asJSON := fs.Bool("json", true, "emit the confirmation result as JSON")
	if err := fs.Parse(args); err != nil {
		return true, err
	}
	if c.pkgPath == "" || c.trPath == "" || len(c.sigPaths) == 0 || len(c.trSigPaths) == 0 || c.trustPath == "" || c.policyPath == "" {
		return true, errors.New("--package, --transition, --signature, --transition-signature, --trust and --policy are required")
	}

	pkgRaw, err := os.ReadFile(c.pkgPath)
	if err != nil {
		return true, err
	}
	trRaw, err := os.ReadFile(c.trPath)
	if err != nil {
		return true, err
	}
	definition, declaration, err := loadPayloads(c)
	if err != nil {
		return false, err
	}

	signatures := make([][]byte, 0, len(c.sigPaths))
	for _, path := range c.sigPaths {
		sig, err := readSignature(path)
		if err != nil {
			return false, err
		}
		signatures = append(signatures, sig)
	}
	transitionSignatures := make([][]byte, 0, len(c.trSigPaths))
	for _, path := range c.trSigPaths {
		sig, err := readSignature(path)
		if err != nil {
			return false, err
		}
		transitionSignatures = append(transitionSignatures, sig)
	}
	roots, err := register.LoadTrustRoots(c.trustPath)
	if err != nil {
		return true, err
	}
	policy, err := loadPolicy(c.policyPath)
	if err != nil {
		return true, err
	}
	if !c.allowStale {
		if err := register.CheckObservedAt(policy.ObservedAt, time.Now().UTC()); err != nil {
			return true, err
		}
	}
	state, err := loadState(c.statePath)
	if err != nil {
		return true, err
	}

	res, confirmErr := schemeadmin.ConfirmSigned(schemeadmin.SignedConfirmation{
		PackageBytes:         pkgRaw,
		Signatures:           signatures,
		TransitionBytes:      trRaw,
		TransitionSignatures: transitionSignatures,
		Definition:           definition,
		Declaration:          declaration,
		Roots:                roots,
		State:                state,
		Policy:               policy,
	})
	if confirmErr == nil && wantAction != "" && res.Action != wantAction {
		res.Verdict = schemeadmin.VerdictReject
		res.Reason = "action_mismatch"
		res.Detail = fmt.Sprintf("transition action %q is not %q", res.Action, wantAction)
		confirmErr = errors.New(res.Detail)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	if *asJSON {
		fmt.Println(string(out))
	} else {
		fmt.Printf("%s %s\n", res.Verdict, res.Reason)
	}
	if confirmErr != nil {
		return false, nil
	}
	pkg, err := schemeadmin.ParsePackage(pkgRaw)
	if err != nil {
		return false, err
	}
	tr, err := schemeadmin.ParseTransition(trRaw)
	if err != nil {
		return false, err
	}
	if c.stateOut != "" {
		confirmation := schemeadmin.Confirmation{
			Package:         pkg,
			Transition:      tr,
			TransitionBytes: trRaw,
			Roots:           roots,
			State:           state,
			Policy:          policy,
		}
		if len(transitionSignatures) > 0 {
			confirmation.TransitionSignature = transitionSignatures[0]
		}
		nextState, err := state.Accept(confirmation, res)
		if err != nil {
			return false, fmt.Errorf("write state: %w", err)
		}
		raw, err := json.MarshalIndent(nextState, "", "  ")
		if err != nil {
			return false, err
		}
		if err := catalog.WriteStateFile(c.stateOut, append(raw, '\n'), true); err != nil {
			return false, err
		}
	}
	return true, nil
}

func loadPayloads(c commonFlags) ([]byte, []byte, error) {
	if c.defPath == "" || c.declPath == "" {
		return nil, nil, errors.New("--definition and --declaration are required: digests are checked against exact bytes")
	}
	d, err := os.ReadFile(c.defPath)
	if err != nil {
		return nil, nil, err
	}
	decl, err := os.ReadFile(c.declPath)
	if err != nil {
		return nil, nil, err
	}
	return d, decl, nil
}

// readSignature decodes a detached PKCS#7 PEM envelope into its DER bytes.
// Signature verification itself happens inside ConfirmSigned, so a caller can
// never hand Confirm a certificate that was not bound to the package bytes.
func readSignature(sigPath string) ([]byte, error) {
	sigPEM, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	if len(sigPEM) > 1<<20 {
		return nil, fmt.Errorf("%s: signature file exceeds 1 MiB", sigPath)
	}
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", sigPath)
	}
	return block.Bytes, nil
}

func runDelegation(args []string) (bool, error) {
	fs := flag.NewFlagSet("delegation", flag.ContinueOnError)
	path := fs.String("delegation", "", "delegation JSON")
	policyPath := fs.String("policy", "", "deployer trust policy JSON")
	allowStale := fs.Bool("allow-stale-clock", false, "accept a policy observed_at far from the wall clock (offline replay)")
	sigPath := fs.String("signature", "", "detached PKCS#7 delegation signature (PEM)")
	trustPath := fs.String("trust", "", "trust anchor PEM bundle")
	if err := fs.Parse(args); err != nil {
		return true, err
	}
	if *path == "" || *policyPath == "" || *sigPath == "" || *trustPath == "" {
		return true, errors.New("--delegation, --policy, --signature and --trust are required")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return true, err
	}
	signature, err := readSignature(*sigPath)
	if err != nil {
		return true, err
	}
	roots, err := register.LoadTrustRoots(*trustPath)
	if err != nil {
		return true, err
	}
	policy, err := loadPolicy(*policyPath)
	if err != nil {
		return true, err
	}
	if !*allowStale {
		if err := register.CheckObservedAt(policy.ObservedAt, time.Now().UTC()); err != nil {
			return true, err
		}
	}
	if err := schemeadmin.ValidateSignedDelegation(raw, signature, roots, policy); err != nil {
		fmt.Printf("reject %s\n", schemeadmin.CodeOf(err))
		return false, nil
	}
	fmt.Println("accept")
	return true, nil
}

func runOperation(args []string) error {
	var c commonFlags
	fs := flag.NewFlagSet("operation", flag.ContinueOnError)
	addCommon(fs, &c)
	if err := fs.Parse(args); err != nil {
		return err
	}
	pkgRaw, err := os.ReadFile(c.pkgPath)
	if err != nil {
		return err
	}
	trRaw, err := os.ReadFile(c.trPath)
	if err != nil {
		return err
	}
	pkg, err := schemeadmin.ParsePackage(pkgRaw)
	if err != nil {
		return err
	}
	tr, err := schemeadmin.ParseTransition(trRaw)
	if err != nil {
		return err
	}
	op, err := schemeadmin.BuildManagementOperation(pkg, tr)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(op, "", "  ")
	fmt.Println(string(out))
	return nil
}

func runKeyID(args []string) error {
	fs := flag.NewFlagSet("keyid", flag.ContinueOnError)
	certPath := fs.String("cert", "", "certificate PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	certs, err := register.LoadCertFile(*certPath)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("no certificate found")
	}
	fmt.Println(schemeadmin.KeyID(certs[0]))
	return nil
}

func loadPolicy(path string) (schemeadmin.TrustPolicy, error) {
	var p schemeadmin.TrustPolicy
	if path == "" {
		return p, errors.New("--policy is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("policy: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return p, errors.New("policy: trailing data after the object")
	}
	return p, nil
}

func loadState(path string) (schemeadmin.RegistryState, error) {
	var s schemeadmin.RegistryState
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return schemeadmin.ParseState(raw)
}
