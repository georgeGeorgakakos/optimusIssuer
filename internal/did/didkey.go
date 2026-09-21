// Package did implements the did:key method for Ed25519 keys.
//
// This package is deliberately tiny and dependency-light because it must
// produce output byte-identical to the verifier inside the OptimusDB agent.
// If the two ever disagree, every credential this service issues will fail to
// verify and the failure will look like a bad signature. Keep the two copies
// in step, or vendor this package into the agent.
package did

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

const (
	// Prefix is the method prefix plus the multibase base58-btc marker.
	Prefix = "did:key:z"

	// multicodec identifier for an Ed25519 public key, varint encoded.
	mcEd25519Byte0 = 0xED
	mcEd25519Byte1 = 0x01
)

// FromEd25519 encodes an Ed25519 public key as a did:key identifier.
//
//	public key (32 bytes)
//	  -> 0xED 0x01 || key        multicodec
//	  -> base58btc                multibase payload
//	  -> "z" || payload           multibase prefix
//	  -> "did:key:" || ...        method prefix
func FromEd25519(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("did: expected a %d byte public key, got %d",
			ed25519.PublicKeySize, len(pub))
	}
	buf := make([]byte, 0, 2+len(pub))
	buf = append(buf, mcEd25519Byte0, mcEd25519Byte1)
	buf = append(buf, pub...)
	return Prefix + base58.Encode(buf), nil
}

// ToEd25519 recovers the public key from a did:key identifier.
//
// This is the whole of DID resolution for this method: a decode, not a lookup.
// No registry is consulted and no network operation occurs, which is what
// allows a verifier to work while completely partitioned.
func ToEd25519(id string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(id, Prefix) {
		return nil, fmt.Errorf("did: %q is not an Ed25519 did:key", id)
	}
	raw, err := base58.Decode(strings.TrimPrefix(id, Prefix))
	if err != nil {
		return nil, fmt.Errorf("did: malformed multibase payload in %q: %w", id, err)
	}
	if len(raw) != 2+ed25519.PublicKeySize {
		return nil, fmt.Errorf("did: unexpected payload length %d", len(raw))
	}
	if raw[0] != mcEd25519Byte0 || raw[1] != mcEd25519Byte1 {
		return nil, fmt.Errorf("did: multicodec %#x %#x is not Ed25519", raw[0], raw[1])
	}
	return ed25519.PublicKey(raw[2:]), nil
}

// VerificationMethod returns the identifier used in a proof, which for this
// method is the DID with its own key as the fragment.
func VerificationMethod(id string) string {
	return id + "#" + strings.TrimPrefix(id, "did:key:")
}

// SubjectOf strips any fragment from a verification method, yielding the DID
// that controls it. A proof is only acceptable when this matches the issuer.
func SubjectOf(verificationMethod string) string {
	if i := strings.Index(verificationMethod, "#"); i >= 0 {
		return verificationMethod[:i]
	}
	return verificationMethod
}

// Valid reports whether a string is a well-formed Ed25519 did:key.
func Valid(id string) bool {
	_, err := ToEd25519(id)
	return err == nil
}
