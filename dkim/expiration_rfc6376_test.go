package dkim

import (
	"strings"
	"testing"
)

func TestRFC6376SignatureExpirationBoundary(t *testing.T) {
	key, publicKey := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	const bodyHash = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	signed := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: bodyHash, Timestamp: 100, SignatureExpiration: 200}
	if err := signed.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	raw := "DKIM-Signature: " + signed.String() + "\r\n"
	for _, tc := range []struct {
		now  int64
		want VerifyStatus
	}{
		{199, VerifyStatusPass},
		{200, VerifyStatusPass},
		{201, VerifyStatusFail},
	} {
		parsed, err := ParseSignature(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsed.verifyWithResolverAt(headers, bodyHash, publicKey, nil, tc.now)
		if result := parsed.VerifyResult; result.Status() != tc.want {
			t.Fatalf("now=%d verification=%s, want %s: %v", tc.now, result.Status(), tc.want, result.Error())
		}
	}
	for _, expiration := range []string{"0", "99", "100"} {
		invalid := strings.Replace(raw, "x=200", "x="+expiration, 1)
		if _, err := ParseSignature(invalid); err == nil {
			t.Fatalf("x=%s accepted with t=100", expiration)
		}
	}
	withoutTimestamp := strings.Replace(raw, "t=100; ", "", 1)
	withoutTimestamp = strings.Replace(withoutTimestamp, "x=200", "x=0", 1)
	parsed, err := ParseSignature(withoutTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	parsed.verifyWithResolverAt(headers, bodyHash, publicKey, nil, 1)
	if result := parsed.VerifyResult; result.Status() != VerifyStatusFail {
		t.Fatalf("x=0 at now=1: verification=%s, want fail", result.Status())
	}
}

func TestRFC6376SignerRejectsInvalidExpiration(t *testing.T) {
	key, _ := regressionKey(t)
	for _, expiration := range []int64{99, 100} {
		sig := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "simple/simple", BodyHash: "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", Timestamp: 100, SignatureExpiration: expiration}
		if err := sig.Sign([]string{"From: a@example.com\r\n"}, key); err == nil {
			t.Fatalf("signed with t=100, x=%d", expiration)
		}
	}
}
