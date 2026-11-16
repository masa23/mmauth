package dkim

import (
	"strings"
	"testing"
)

func TestRFC6376RevokedDomainKey(t *testing.T) {
	key, _ := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	signed := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := signed.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignature("DKIM-Signature: " + signed.String() + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	parsed.VerifyWithResolver(headers, signed.BodyHash, nil, keyVersionResolver{record: "v=DKIM1; k=ed25519; p="})
	if result := parsed.VerifyResult; result.Status() != VerifyStatusPermErr || result.Error() == nil || !strings.Contains(result.Error().Error(), "key revoked") {
		t.Fatalf("revoked key result=%s error=%v", result.Status(), result.Error())
	}
}
