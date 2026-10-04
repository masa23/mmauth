package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/header"
)

func regressionKey(t *testing.T) (ed25519.PrivateKey, *domainkey.DomainKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return key, &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
}
func TestRegressionRepeatedHeaders(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n", "Received: by last.example.com\r\n", "Received: by first.example.com\r\n"}
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := d.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	parsed, e := ParseSignature("DKIM-Signature: " + d.String() + "\r\n")
	if e != nil {
		t.Fatal(e)
	}
	parsed.Verify(headers, d.BodyHash, dk)
	if parsed.VerifyResult.Status() != VerifyStatusPass {
		t.Errorf("Sign->Parse->Verify with repeated headers: %s %v", parsed.VerifyResult.Status(), parsed.VerifyResult.Error())
	}
}
func TestRegressionWhitespaceBeforeEquals(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	body := sha256.Sum256([]byte("body\r\n"))
	bh := base64.StdEncoding.EncodeToString(body[:])
	raw := "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=s; h=from; bh=" + bh + "; b ="
	sig, e := header.SignerWithOmitLastCRLF(append(headers, raw+"\r\n"), key, canonical.Relaxed, crypto.SHA256, true)
	if e != nil {
		t.Fatal(e)
	}
	d, e := ParseSignature(raw + sig + "\r\n")
	if e != nil {
		t.Fatal(e)
	}
	d.Verify(headers, bh, dk)
	if d.VerifyResult.Status() != VerifyStatusPass {
		t.Errorf("valid b = signature: %s %v", d.VerifyResult.Status(), d.VerifyResult.Error())
	}
}
func TestRegressionMalformedSibling(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := d.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	sigs, e := ParseDKIMHeaders(append(headers, "DKIM-Signature: broken\r\n", "DKIM-Signature: "+d.String()+"\r\n"))
	if e != nil {
		t.Fatalf("one malformed signature discards valid sibling: %v (sigs=%v)", e, sigs)
	}
	if len(*sigs) != 2 {
		t.Fatalf("got %d signatures", len(*sigs))
	}
	for _, sig := range *sigs {
		sig.Verify(headers, d.BodyHash, dk)
	}
	if (*sigs)[0].VerifyResult.Status() != VerifyStatusPermErr || (*sigs)[1].VerifyResult.Status() != VerifyStatusPass {
		t.Fatal("malformed signature must not discard the valid sibling")
	}

}
func TestRegressionUnknownKeyRestrictions(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := d.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	for _, restriction := range []string{"h=sha512", "s=other"} {
		t.Run(restriction, func(t *testing.T) {
			restricted, e := domainkey.ParseDomainKeyRecord("v=DKIM1; k=ed25519; p=" + dk.PublicKey + "; " + restriction)
			if e != nil {
				t.Fatal(e)
			}
			parsed, e := ParseSignature("DKIM-Signature: " + d.String() + "\r\n")
			if e != nil {
				t.Fatal(e)
			}
			parsed.Verify(headers, d.BodyHash, &restricted)
			if parsed.VerifyResult.Status() == VerifyStatusPass {
				t.Errorf("key restriction %s accepted as unrestricted", restriction)
			}
		})
	}
}

func TestExplicitZeroLengthRoundTrip(t *testing.T) {
	key, dk := regressionKey(t)
	empty := sha256.Sum256(nil)
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", LimitSet: true, BodyHash: base64.StdEncoding.EncodeToString(empty[:])}
	headers := []string{"From: a@example.com\r\n"}
	if err := d.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignature("DKIM-Signature: " + d.String() + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.LimitSet || parsed.Limit != 0 || !parsed.GetCanonicalizationAndAlgorithm().LimitSet {
		t.Fatal("explicit l=0 lost")
	}
	parsed.Verify(headers, d.BodyHash, dk)
	if parsed.VerifyResult.Status() != VerifyStatusPass {
		t.Fatal(parsed.VerifyResult.Error())
	}
}
