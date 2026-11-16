package mldsa44_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/masa23/mmauth/dkim2"
	"github.com/masa23/mmauth/dkim2/mldsa44"
)

type publicKeyResolver struct{ public []byte }

// LookupTXT publishes only the synthetic test signing key.
func (r publicKeyResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name != "pq._domainkey.example.test" {
		return nil, &net.DNSError{IsNotFound: true, Name: name}
	}
	return []string{"v=DKIM1; k=mldsa44; p=" + base64.StdEncoding.EncodeToString(r.public)}, nil
}

// TestPublicKeyAPIAuthenticatesMail exercises key generation, key persistence,
// and DKIM2 signing through externally accessible package APIs only.
func TestPublicKeyAPIAuthenticatesMail(t *testing.T) {
	var seed [mldsa44.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	public, private := mldsa44.NewKeyFromSeed(&seed)
	var _ crypto.Signer = private
	packed, err := private.MarshalBinary()
	if err != nil || len(packed) != mldsa44.PrivateKeySize {
		t.Fatalf("private key serialization: %v", err)
	}
	var restored mldsa44.PrivateKey
	if err := restored.UnmarshalBinary(packed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Public().(*mldsa44.PublicKey).Bytes(), public.Bytes()) {
		t.Fatal("public key changed after restoring the private key")
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil || len(publicBytes) != mldsa44.PublicKeySize {
		t.Fatalf("public key serialization: %v", err)
	}
	var restoredPublic mldsa44.PublicKey
	if err := restoredPublic.UnmarshalBinary(publicBytes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredPublic.Bytes(), public.Bytes()) {
		t.Fatal("public key bytes changed")
	}
	when := time.Unix(1700000000, 0)
	envelope := dkim2.Envelope{MailFrom: "<alice@example.test>", RcptTo: []string{"<bob@destination.test>"}}
	wire, err := dkim2.Sign([]byte("From: alice@example.test\r\nSubject: bundled key\r\n\r\nbody\r\n"), dkim2.SignOptions{
		Domain: "example.test", Selector: "pq", Key: &restored, Timestamp: when, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := dkim2.Verify(wire, envelope, dkim2.VerifyOptions{Resolver: publicKeyResolver{publicBytes}, Now: when})
	if result.Status != dkim2.Pass {
		t.Fatalf("bundled key failed DKIM2: %+v", result)
	}
}

// TestPublicPrimitiveContext checks explicit context binding and deterministic
// generation without requiring consumers to import an internal package.
func TestPublicPrimitiveContext(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, mldsa44.SeedSize)
	public, private, err := mldsa44.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	var fixed [mldsa44.SeedSize]byte
	copy(fixed[:], seed)
	expected, _ := mldsa44.NewKeyFromSeed(&fixed)
	if !bytes.Equal(public.Bytes(), expected.Bytes()) {
		t.Fatal("key-generation seed semantics changed")
	}
	signature := make([]byte, mldsa44.SignatureSize)
	message := []byte("test message")
	if err := mldsa44.SignTo(private, message, []byte("DKIM2"), false, signature); err != nil {
		t.Fatal(err)
	}
	if !mldsa44.Verify(public, message, []byte("DKIM2"), signature) || mldsa44.Verify(public, message, nil, signature) {
		t.Fatal("signature context binding failed")
	}
	if _, _, err := mldsa44.GenerateKey(bytes.NewReader(nil)); err == nil {
		t.Fatal("failed entropy source accepted")
	}
	if err := private.UnmarshalBinary(nil); err == nil {
		t.Fatal("invalid private key encoding accepted")
	}
	if err := public.UnmarshalBinary(nil); err == nil {
		t.Fatal("invalid public key encoding accepted")
	}
}
