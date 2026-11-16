package dkim2

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/masa23/mmauth/dkim2/internal/circl/sign/mldsa/mldsa44"
)

func TestRSAPublicKeyResourceLimits(t *testing.T) {
	for _, bits := range []int{1024, 2048, 4096, maxRSAKeyBits, maxRSAKeyBits + 1} {
		// Verification only requires a positive modulus. Avoid costly private-key
		// generation when testing the boundary enforced before RSA arithmetic.
		pub := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), bits-1, 1), E: 65537}
		pkix, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		for name, der := range map[string][]byte{"pkcs1": x509.MarshalPKCS1PublicKey(pub), "spki": pkix} {
			r := records{"s1._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)}}
			key, err := lookupKey(r, "example.com", "s1", "rsa-sha256")
			if bits > maxRSAKeyBits {
				var permanent *permanentKeyError
				if !errors.As(err, &permanent) || !strings.Contains(err.Error(), "exceeds 8192 bits") {
					t.Fatalf("%s %d-bit key: expected permanent size rejection, got %v", name, bits, err)
				}
			} else if err != nil || key.public.(*rsa.PublicKey).N.BitLen() != bits {
				t.Fatalf("%s %d-bit key: %v", name, bits, err)
			}
		}
	}
}

func TestDNSKeyEncodedSizeLimits(t *testing.T) {
	for _, tc := range []struct {
		algorithm string
		keyType   string
		limit     int
	}{
		{"rsa-sha256", "rsa", maxRSAPublicKeyBytes},
		{"ed25519-sha256", "ed25519", 32},
		{"mldsa44", "mldsa44", mldsa44.PublicKeySize},
	} {
		for _, excess := range []int{1, 3} {
			// One extra byte may fit in the same base64 quartet; three cannot.
			encoded := base64.StdEncoding.EncodeToString(make([]byte, tc.limit+excess))
			r := records{"s1._domainkey.example.com": {"v=DKIM1; k=" + tc.keyType + "; p=" + encoded}}
			_, err := lookupKey(r, "example.com", "s1", tc.algorithm)
			var permanent *permanentKeyError
			if !errors.As(err, &permanent) || !strings.Contains(err.Error(), "exceeds size limit") {
				t.Fatalf("%s +%d bytes: expected permanent size rejection, got %v", tc.keyType, excess, err)
			}
		}
	}
	r := records{"s1._domainkey.example.com": {"v=DKIM1; p=AA==; x=" + strings.Repeat("x", maxDNSTXTRecordBytes)}}
	if _, err := lookupKey(r, "example.com", "s1", "rsa-sha256"); err == nil || !strings.Contains(err.Error(), "TXT record exceeds size limit") {
		t.Fatalf("oversized TXT record: %v", err)
	}
}

// CIRCL PR #606: a public key already returned to a caller must not inherit
// subsequent changes to the private key's cached public-key hash (tr).
func TestPublicTrIsIndependentOfPrivate(t *testing.T) {
	testPublicKeyIndependentOfPrivate(t, false)
}

func TestPublicMatrixIsIndependentOfPrivate(t *testing.T) {
	testPublicKeyIndependentOfPrivate(t, true)
}

func testPublicKeyIndependentOfPrivate(t *testing.T, replaceEntireKey bool) {
	t.Helper()
	for _, fromPublic := range []bool{false, true} {
		var seed [mldsa44.SeedSize]byte
		pk, sk := mldsa44.NewKeyFromSeed(&seed)
		if fromPublic {
			pk = sk.Public().(*mldsa44.PublicKey)
		}
		message, context := []byte("public key independence"), []byte("DKIM2")
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(sk, message, context, false, sig); err != nil {
			t.Fatal(err)
		}
		if !mldsa44.Verify(pk, message, context, sig) {
			t.Fatal("baseline signature failed")
		}
		publicBefore := pk.Bytes()
		var packed [mldsa44.PrivateKeySize]byte
		sk.Pack(&packed)
		if replaceEntireKey {
			seed[0] = 1
			_, replacement := mldsa44.NewKeyFromSeed(&seed)
			replacement.Pack(&packed)
		} else {
			// ML-DSA private-key encoding is rho (32), K (32), tr (64), ...
			// Change only tr so no other cached public-key values are affected.
			packed[64] ^= 1
		}
		sk.Unpack(&packed)
		if !bytes.Equal(publicBefore, pk.Bytes()) || !mldsa44.Verify(pk, message, context, sig) {
			t.Fatalf("returned public key changed after private Unpack; Public=%v", fromPublic)
		}
	}
}
