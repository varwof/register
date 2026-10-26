// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	// MaxReportBytes bounds a decoded report payload before it is parsed.
	MaxReportBytes = 8 << 20
	// MaxEnvelopeSignatures bounds the signature list so verification cannot be
	// turned into an unbounded CPU loop.
	MaxEnvelopeSignatures = 64
	// MaxSignatureBytes bounds one decoded signature.
	MaxSignatureBytes = 64 << 10
)

// Signature is one DSSE signature entry.  Sig is base64url (unpadded) over the
// PAE bytes.  KeyID is an unauthenticated hint.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE v1.0.2 JSON envelope.  Unlike a []byte field serialized by
// encoding/json (which uses standard base64 with padding), the payload and each
// signature are base64url without padding, as DSSE specifies.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// EnvelopeBytes decodes the payload and signatures of a DSSE envelope,
// rejecting non-canonical base64url (including standard base64 with padding).
func EnvelopeBytes(env *Envelope) (payload []byte, signatures [][]byte, err error) {
	if env == nil {
		return nil, nil, fmt.Errorf("envelope is nil")
	}
	if len(env.Signatures) > MaxEnvelopeSignatures {
		return nil, nil, fmt.Errorf("envelope has %d signatures, limit is %d",
			len(env.Signatures), MaxEnvelopeSignatures)
	}
	payload, err = decodeBase64URL("payload", env.Payload)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) > MaxReportBytes {
		return nil, nil, fmt.Errorf("payload is %d bytes, limit is %d", len(payload), MaxReportBytes)
	}
	signatures = make([][]byte, 0, len(env.Signatures))
	for i, signature := range env.Signatures {
		raw, err := decodeBase64URL(fmt.Sprintf("signature %d", i), signature.Sig)
		if err != nil {
			return nil, nil, err
		}
		if len(raw) > MaxSignatureBytes {
			return nil, nil, fmt.Errorf("signature %d is %d bytes, limit is %d",
				i, len(raw), MaxSignatureBytes)
		}
		signatures = append(signatures, raw)
	}
	return payload, signatures, nil
}

// DecodeEnvelope parses a DSSE envelope from JSON and validates the base64url
// encoding of its payload and signatures.
func DecodeEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > 3*MaxReportBytes {
		return nil, fmt.Errorf("envelope JSON is %d bytes, limit is %d", len(raw), 3*MaxReportBytes)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	if _, _, err := EnvelopeBytes(&env); err != nil {
		return nil, err
	}
	return &env, nil
}

// decodeBase64URL decodes unpadded base64url and rejects any input that does not
// round-trip to the same string (padding, standard alphabet, trailing bits).
func decodeBase64URL(field, value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not unpadded base64url: %w", field, err)
	}
	if base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s is not canonical base64url", field)
	}
	return raw, nil
}
