package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestDKIMInvalidDNSKeyTypes(t *testing.T) {
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := parsedKey.(*rsa.PrivateKey)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(pub)
	headers := []string{"From: a@example.com\r\n"}
	sig := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := sig.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	for _, tag := range []string{"", "k=rsa; ", "k=unsupported; ", "k=; ", "k=rsa:unsupported; "} {
		t.Run(tag, func(t *testing.T) {
			parsed, e := ParseSignature("DKIM-Signature: " + sig.String() + "\r\n")
			if e != nil {
				t.Fatal(e)
			}
			parsed.VerifyWithResolver(headers, sig.BodyHash, nil, keyVersionResolver{"v=DKIM1; " + tag + "p=" + publicKey})
			want := VerifyStatusPass
			if tag != "" && tag != "k=rsa; " {
				want = VerifyStatusPermErr
			}
			if parsed.VerifyResult.Status() != want {
				t.Fatalf("status=%s want=%s error=%v", parsed.VerifyResult.Status(), want, parsed.VerifyResult.Error())
			}
			if want == VerifyStatusPermErr && !errors.Is(parsed.VerifyResult.Error(), domainkey.ErrInvalidKeyType) {
				t.Fatal(parsed.VerifyResult.Error())
			}
		})
	}
}
