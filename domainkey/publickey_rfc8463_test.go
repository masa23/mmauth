package domainkey

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"
)

func TestRFC8463Ed25519PublicKeyLength(t *testing.T) {
	for _, size := range []int{31, 32, 33} {
		pub, err := ParseDKIMPublicKey(make([]byte, size), KeyTypeED25519)
		if size == ed25519.PublicKeySize {
			if err != nil {
				t.Fatalf("32-octet key rejected: %v", err)
			}
			if _, ok := pub.(ed25519.PublicKey); !ok {
				t.Fatalf("key type=%T, want ed25519.PublicKey", pub)
			}
		} else if err == nil {
			t.Fatalf("%d-octet key accepted", size)
		}
	}
}

func TestRFC8463Ed25519RejectsPKIXPublicKey(t *testing.T) {
	encoded, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDKIMPublicKey(encoded, KeyTypeED25519); err == nil {
		t.Fatal("PKIX-encoded Ed25519 key accepted instead of raw 32-octet key")
	}
}
