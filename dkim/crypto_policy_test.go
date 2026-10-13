package dkim

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

type countTXTResolver struct{ calls int }

func (r *countTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.calls++
	return nil, fmt.Errorf("unexpected DNS lookup")
}

// Build an independently signed DKIM header so a verifier policy failure
// cannot be confused with a broken signature produced by Signature.Sign.
func manuallySignedRSA(t *testing.T, key *rsa.PrivateKey, algorithm SignatureAlgorithm) (*Signature, []string, string, *domainkey.DomainKey) {
	t.Helper()
	headers := []string{"From: a@example.com\r\n"}
	bodyHash := "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
	hash := crypto.SHA256
	var digest []byte
	if algorithm == SignatureAlgorithmRSA_SHA1 {
		hash = crypto.SHA1
		bodyHash = "uoq1oCgLlTqpdDX/iUbLy7J1Wic="
	}
	raw := "DKIM-Signature: v=1; a=" + string(algorithm) + "; c=simple/simple; d=example.com; s=s; h=From; bh=" + bodyHash + "; b="
	if hash == crypto.SHA1 {
		sum := sha1.Sum([]byte(headers[0] + raw))
		digest = sum[:]
	} else {
		sum := sha256.Sum256([]byte(headers[0] + raw))
		digest = sum[:]
	}
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ParseSignature(raw + base64.StdEncoding.EncodeToString(signed) + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	return sig, headers, bodyHash, &domainkey.DomainKey{KeyType: domainkey.KeyTypeRSA, PublicKey: publicKey}
}

func TestRFC8301RejectsRSA_SHA1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	headers := []string{"From: a@example.com\r\n"}
	signer := &Signature{Version: 1, Algorithm: SignatureAlgorithmRSA_SHA1, Domain: "example.com", Selector: "s", Canonicalization: "simple/simple", BodyHash: "uoq1oCgLlTqpdDX/iUbLy7J1Wic="}
	if err := signer.Sign(headers, key); err == nil {
		t.Fatal("rsa-sha1 signing succeeded")
	}
	verified, headers, bodyHash, publicKey := manuallySignedRSA(t, key, SignatureAlgorithmRSA_SHA1)
	verified.Verify(headers, bodyHash, publicKey)
	if result := verified.VerifyResult; result.Status() != VerifyStatusPermErr || result.Error() == nil {
		t.Fatalf("rsa-sha1 verification result=%s error=%v", result.Status(), result.Error())
	}
	verified, headers, bodyHash, _ = manuallySignedRSA(t, key, SignatureAlgorithmRSA_SHA1)
	resolver := &countTXTResolver{}
	verified.VerifyWithResolver(headers, bodyHash, nil, resolver)
	if result := verified.VerifyResult; result.Status() != VerifyStatusPermErr || resolver.calls != 0 {
		t.Fatalf("rsa-sha1 result=%s, DNS calls=%d", result.Status(), resolver.calls)
	}
	verified.raw = ""
	verified.VerifyWithResolver(headers, bodyHash, nil, resolver)
	if result := verified.VerifyResult; result.Status() != VerifyStatusPermErr || resolver.calls != 0 {
		t.Fatalf("direct rsa-sha1 result=%s, DNS calls=%d", result.Status(), resolver.calls)
	}
}

func TestRFC8301RSAKeySizeBoundaries(t *testing.T) {
	for _, bits := range []int{1023, 1024, 2048, 4096} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			headers := []string{"From: a@example.com\r\n"}
			signer := &Signature{Version: 1, Algorithm: SignatureAlgorithmRSA_SHA256, Domain: "example.com", Selector: "s", Canonicalization: "simple/simple", BodyHash: "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="}
			signErr := signer.Sign(headers, key)
			if bits < 1024 {
				if signErr == nil {
					t.Fatal("short RSA key signed a message")
				}
			} else if signErr != nil {
				t.Fatal(signErr)
			}
			verified, signedHeaders, bodyHash, publicKey := manuallySignedRSA(t, key, SignatureAlgorithmRSA_SHA256)
			verified.Verify(signedHeaders, bodyHash, publicKey)
			want := VerifyStatusPass
			if bits < 1024 {
				want = VerifyStatusPermErr
			}
			if result := verified.VerifyResult; result.Status() != want {
				t.Fatalf("verification=%s, want %s: %v", result.Status(), want, result.Error())
			}
			if bits < 1024 && !strings.Contains(verified.VerifyResult.Error().Error(), "1024") {
				t.Fatalf("short key failure reason: %v", verified.VerifyResult.Error())
			}
			if bits < 1024 {
				verified, signedHeaders, bodyHash, _ = manuallySignedRSA(t, key, SignatureAlgorithmRSA_SHA256)
				verified.VerifyWithResolver(signedHeaders, bodyHash, nil, keyVersionResolver{record: "v=DKIM1; k=rsa; p=" + publicKey.PublicKey})
				if result := verified.VerifyResult; result.Status() != VerifyStatusPermErr {
					t.Fatalf("DNS key verification=%s, want permerror: %v", result.Status(), result.Error())
				}
			}
		})
	}
}

func TestDKIMSignRejectsNilKey(t *testing.T) {
	var typedNil *rsa.PrivateKey
	for _, key := range []crypto.Signer{nil, typedNil} {
		for _, algorithm := range []SignatureAlgorithm{"", SignatureAlgorithmRSA_SHA256} {
			signer := &Signature{Version: 1, Algorithm: algorithm, Canonicalization: "simple/simple"}
			if err := signer.Sign([]string{"From: a@example.com\r\n"}, key); err == nil {
				t.Fatalf("signed with nil key %T and algorithm %q", key, algorithm)
			}
		}
	}
}

func TestDKIMSignRejectsAlgorithmKeyMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		algorithm SignatureAlgorithm
		key       crypto.Signer
	}{
		{SignatureAlgorithmRSA_SHA256, edKey},
		{SignatureAlgorithmED25519_SHA256, rsaKey},
	} {
		signer := &Signature{Version: 1, Algorithm: tc.algorithm, Canonicalization: "simple/simple"}
		if err := signer.Sign([]string{"From: a@example.com\r\n"}, tc.key); err == nil {
			t.Errorf("signed with %s and %T", tc.algorithm, tc.key)
		}
	}
}
