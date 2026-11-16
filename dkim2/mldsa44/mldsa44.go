// Package mldsa44 supplies Go 1.19-compatible ML-DSA-44 keys for DKIM2.
// It exposes the bundled CIRCL implementation without requiring consumers to
// override module dependencies. PrivateKey implements crypto.Signer and can
// be passed directly to dkim2.SignOptions.Key.
package mldsa44

import (
	"io"

	implementation "github.com/masa23/mmauth/dkim2/internal/circl/sign/mldsa/mldsa44"
)

const (
	// SeedSize is the byte length of a deterministic key-generation seed.
	SeedSize = implementation.SeedSize
	// PublicKeySize is the byte length of a packed public key for DNS.
	PublicKeySize = implementation.PublicKeySize
	// PrivateKeySize is the byte length of a packed private key.
	PrivateKeySize = implementation.PrivateKeySize
	// SignatureSize is the byte length of an ML-DSA-44 signature.
	SignatureSize = implementation.SignatureSize
)

// PublicKey is an ML-DSA-44 public key with binary serialization methods.
type PublicKey = implementation.PublicKey

// PrivateKey is an ML-DSA-44 private key implementing crypto.Signer.
// Use dkim2.Sign to apply the DKIM2-specific message and context rules.
type PrivateKey = implementation.PrivateKey

// GenerateKey generates a key pair from random, defaulting to crypto/rand.Reader
// when random is nil. Private keys must be kept secret by the caller.
func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	return implementation.GenerateKey(random)
}

// NewKeyFromSeed derives a key pair from an exactly SeedSize-byte seed.
// The seed is private key material and must be kept secret by the caller.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	return implementation.NewKeyFromSeed(seed)
}

// SignTo writes a pure ML-DSA-44 signature over message with an explicit context.
// It panics if signature is shorter than SignatureSize. DKIM2 uses context
// "DKIM2"; dkim2.Sign handles that rule when signing mail.
func SignTo(private *PrivateKey, message, context []byte, randomized bool, signature []byte) error {
	return implementation.SignTo(private, message, context, randomized, signature)
}

// Verify checks a pure ML-DSA-44 signature and its explicit context.
func Verify(public *PublicKey, message, context, signature []byte) bool {
	return implementation.Verify(public, message, context, signature)
}
