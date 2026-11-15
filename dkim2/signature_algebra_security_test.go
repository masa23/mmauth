package dkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// Section 14.6 combines individual signature results. A size or key-policy
// rejection must not become a parse error that discards other sig-any groups.
func TestSignaturePolicyRejectionsPreserveAlgebra(t *testing.T) {
	rsaRecord := func(bits int) string {
		modulus := new(big.Int).SetBit(big.NewInt(1), bits-1, 1)
		pub := &rsa.PublicKey{N: modulus, E: 65537}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	}
	key := edKey()
	for _, test := range []struct {
		name, algorithm, record string
		length                  int
		want                    Status
	}{
		{"RSA boundary", "rsa-sha256", rsaRecord(maxRSAKeyBits), maxRSASignatureBytes, Fail},
		{"RSA oversized same quartet", "rsa-sha256", rsaRecord(maxRSAKeyBits), maxRSASignatureBytes + 1, PermError},
		{"RSA oversized new quartet", "rsa-sha256", rsaRecord(maxRSAKeyBits), maxRSASignatureBytes + 3, PermError},
		{"Ed25519 short", "ed25519-sha256", keyRecord(key), ed25519.SignatureSize - 1, Fail},
		{"Ed25519 long", "ed25519-sha256", keyRecord(key), ed25519.SignatureSize + 1, Fail},
		{"Ed25519 much longer", "ed25519-sha256", keyRecord(key), ed25519.SignatureSize + 3, Fail},
		{"MLDSA short", "mldsa44", "", mldsa44.SignatureSize - 1, Fail},
		{"MLDSA long", "mldsa44", "", mldsa44.SignatureSize + 1, Fail},
		{"MLDSA much longer", "mldsa44", "", mldsa44.SignatureSize + 3, Fail},
		{"unknown algorithm", "future", "", 16, PermError},
		{"missing key", "ed25519-sha256", "", ed25519.SignatureSize, PermError},
		{"insecure key", "rsa-sha256", rsaRecord(512), 64, PermError},
		{"over-limit key", "rsa-sha256", rsaRecord(maxRSAKeyBits + 1), maxRSASignatureBytes, PermError},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, combination := range []struct {
				name, separator string
				goodFirst       bool
				want            Status
			}{
				{"individual", "", false, test.want},
				{"OR rejected first", "|", false, Pass},
				{"OR valid first", "|", true, Pass},
				{"AND rejected first", ",", false, test.want},
				{"AND valid first", ",", true, test.want},
			} {
				t.Run(combination.name, func(t *testing.T) {
					wire, envelope := signatureAlgebraWire(t, test.algorithm, bytes.Repeat([]byte{0}, test.length), combination.separator, combination.goodFirst)
					if _, err := Parse(wire); err != nil {
						t.Fatalf("individual policy rejection became syntax failure: %v", err)
					}
					resolver := records{"good._domainkey.example.com": {keyRecord(key)}}
					if test.record != "" {
						resolver["bad._domainkey.example.com"] = []string{test.record}
					}
					got := Verify(wire, envelope, VerifyOptions{Resolver: resolver, Now: testTime})
					if got.Status != combination.want {
						t.Fatalf("status=%s, want %s: %v", got.Status, combination.want, got.Err)
					}
					if got.Err != nil && !strings.Contains(got.Err.Error(), "bad") {
						t.Fatalf("error omits failing selector: %v", got.Err)
					}
				})
			}
		})
	}
}

func signatureAlgebraWire(t *testing.T, badAlgorithm string, badValue []byte, separator string, goodFirst bool) ([]byte, Envelope) {
	t.Helper()
	envelope := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	m, err := Parse(original())
	if err != nil {
		t.Fatal(err)
	}
	hh, err := headerDigest(m.Headers, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	bh, err := bodyDigest(m.Body, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	mi := fmt.Sprintf("Message-Instance: m=1; h=sha256:%s:%s;\r\n", hh, bh)
	bad, good := "bad:"+badAlgorithm+":", "good:ed25519-sha256:"
	value := bad
	if separator != "" {
		value = bad + separator + good
		if goodFirst {
			value = good + separator + bad
		}
	}
	template := fmt.Sprintf("DKIM2-Signature: i=1; m=1; t=%d; mf=%s; rt=%s; d=example.com; s=%s;\r\n", testTime.Unix(), base64.StdEncoding.EncodeToString([]byte(envelope.MailFrom)), base64.StdEncoding.EncodeToString([]byte(envelope.RcptTo[0])), value)
	input, err := signatureInput([]Instance{{Number: 1, Raw: mi}}, nil, template)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(input)
	field := strings.Replace(template, bad, bad+foldBase64(base64.StdEncoding.EncodeToString(badValue)), 1)
	if separator != "" {
		field = strings.Replace(field, good, good+foldBase64(base64.StdEncoding.EncodeToString(ed25519.Sign(edKey(), hash[:]))), 1)
	}
	return append([]byte(field+mi), original()...), envelope
}
