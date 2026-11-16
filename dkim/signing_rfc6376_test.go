package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var testFWS = regexp.MustCompile(`\r\n[ \t]+`)
var testWSP = regexp.MustCompile(`[ \t]+`)

// canonicalizeRFC6376Test is deliberately separate from the production
// canonicalizer; the signing test checks the emitted signature with stdlib crypto.
func canonicalizeRFC6376Test(field string, mode string) string {
	if mode == "simple" {
		return field
	}
	field = testFWS.ReplaceAllString(field, " ")
	name, value, _ := strings.Cut(field, ":")
	value = strings.TrimSpace(value)
	return strings.ToLower(name) + ":" + testWSP.ReplaceAllString(value, " ") + "\r\n"
}

func TestRFC6376SignerCanonicalizationAndCryptoMatrix(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	edKey := ed25519.NewKeyFromSeed(seed)
	headers := []string{
		"From: Alice <alice@example.com>\r\n",
		"Subject:  Hello\t World  \r\n",
	}
	bodyHash := sha256.Sum256([]byte("hello\r\n"))
	for _, key := range []struct {
		name string
		key  crypto.Signer
		algo SignatureAlgorithm
	}{
		{"rsa", rsaKey, SignatureAlgorithmRSA_SHA256},
		{"ed25519", edKey, SignatureAlgorithmED25519_SHA256},
	} {
		for _, hcanon := range []string{"simple", "relaxed"} {
			for _, bcanon := range []string{"simple", "relaxed"} {
				t.Run(fmt.Sprintf("%s/%s/%s", key.name, hcanon, bcanon), func(t *testing.T) {
					sig := &Signature{
						Version:          1,
						Algorithm:        key.algo,
						Domain:           "example.com",
						Selector:         "s",
						Canonicalization: hcanon + "/" + bcanon,
						BodyHash:         base64.StdEncoding.EncodeToString(bodyHash[:]),
						Timestamp:        1700000000,
					}
					if err := sig.Sign(headers, key.key); err != nil {
						t.Fatal(err)
					}
					if sig.Headers != "From:Subject" {
						t.Fatalf("h=%q", sig.Headers)
					}
					encoded := sig.Signature
					sig.Signature = ""
					bare := "DKIM-Signature: " + sig.String() + "\r\n"
					sig.Signature = encoded
					if !strings.Contains(bare, "bh="+base64.StdEncoding.EncodeToString(bodyHash[:])) {
						t.Fatalf("body hash absent from DKIM-Signature: %q", bare)
					}
					input := canonicalizeRFC6376Test(headers[0], hcanon) + canonicalizeRFC6376Test(headers[1], hcanon) + canonicalizeRFC6376Test(bare, hcanon)
					input = strings.TrimSuffix(input, "\r\n")
					digest := sha256.Sum256([]byte(input))
					signature, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					switch publicKey := key.key.Public().(type) {
					case *rsa.PublicKey:
						if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
							t.Fatalf("independent RSA verification failed: %v", err)
						}
					case ed25519.PublicKey:
						if !ed25519.Verify(publicKey, digest[:], signature) {
							t.Fatal("independent Ed25519 verification failed")
						}
					}
				})
			}
		}
	}
}
