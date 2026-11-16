package dkim

import (
	"encoding/json"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestRegressionCachedKeyRestrictions(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := d.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		restriction string
		want        VerifyStatus
	}{
		{"h=sha512", VerifyStatusPermErr}, {"s=other", VerifyStatusPermErr},
		{"h=", VerifyStatusPermErr}, {"s=", VerifyStatusPermErr},
		{"", VerifyStatusPass}, {"s=*", VerifyStatusPass},
		{"h=sha512:sha256; s=other:email", VerifyStatusPass},
	} {
		restriction := tc.restriction
		t.Run(restriction, func(t *testing.T) {
			restricted, err := domainkey.ParseDomainKeyRecord("v=DKIM1; k=ed25519; p=" + dk.PublicKey + "; " + restriction)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseSignature("DKIM-Signature: " + d.String() + "\r\n")
			if err != nil {
				t.Fatal(err)
			}
			parsed.Verify(headers, d.BodyHash, &restricted)
			before := parsed.VerifyResult.Status()
			raw, err := json.Marshal(restricted)
			if err != nil {
				t.Fatal(err)
			}
			var restored domainkey.DomainKey
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			parsed.Verify(headers, d.BodyHash, &restored)
			if before != tc.want || parsed.VerifyResult.Status() != tc.want {
				t.Errorf("key policy lost after JSON round trip: before=%s after=%s JSON=%s", before, parsed.VerifyResult.Status(), raw)
			}
		})
	}
}
