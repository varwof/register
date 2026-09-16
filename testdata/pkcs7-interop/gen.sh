#!/usr/bin/env bash
# Regenerate the PKCS#7 interop fixture (test-only material).
#
# Direction pinned by the committed fixture: openssl signs -> the register Go
# verifier must accept.  The reverse direction (Go signs -> openssl verifies)
# needs a private key, so it is exercised at test time instead and no private
# key is ever committed.
#
# Usage: testdata/pkcs7-interop/gen.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- root CA (self-signed, EC P-256) ---
openssl ecparam -name prime256v1 -genkey -noout -out "$work/root.key.pem"
openssl req -x509 -new -key "$work/root.key.pem" -sha256 -days 36500 \
  -subj "/O=varwof test/CN=varwof interop test root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$here/root.pem"

# --- signer leaf: codeSigning EKU, the usage the Go verifier requires ---
openssl ecparam -name prime256v1 -genkey -noout -out "$work/signer.key.pem"
openssl req -new -key "$work/signer.key.pem" \
  -subj "/O=varwof test/CN=varwof interop test signer" -out "$work/signer.csr"
openssl x509 -req -in "$work/signer.csr" -sha256 -days 36500 \
  -CA "$here/root.pem" -CAkey "$work/root.key.pem" \
  -CAserial "$work/root.srl" -CAcreateserial \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n') \
  -out "$here/signer.pem"

# --- detached PKCS#7 over content.json ---
openssl cms -sign -binary -in "$here/content.json" \
  -signer "$here/signer.pem" -inkey "$work/signer.key.pem" \
  -certfile "$here/root.pem" -outform PEM -out "$here/openssl.p7s"

# --- unrelated CA: a trust root the signature MUST NOT verify against ---
openssl ecparam -name prime256v1 -genkey -noout -out "$work/unrelated.key.pem"
openssl req -x509 -new -key "$work/unrelated.key.pem" -sha256 -days 36500 \
  -subj "/O=varwof test/CN=varwof interop unrelated CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$here/unrelated-ca.pem"

echo "regenerated: root.pem signer.pem openssl.p7s unrelated-ca.pem"
