package dkim

import "testing"

func TestDKIMRejectsModifiedUnsupportedAlgorithm(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	sig := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := sig.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	raw := "DKIM-Signature: " + sig.String() + "\r\n"
	for _, algorithm := range []SignatureAlgorithm{SignatureAlgorithmED25519_SHA256, "", "unsupported"} {
		t.Run(string(algorithm), func(t *testing.T) {
			parsed, err := ParseSignature(raw)
			if err != nil {
				t.Fatal(err)
			}
			parsed.Algorithm = algorithm
			parsed.Verify(headers, sig.BodyHash, dk)
			want := VerifyStatusPermErr
			if algorithm == SignatureAlgorithmED25519_SHA256 {
				want = VerifyStatusPass
			}
			if result := parsed.VerifyResult; result.Status() != want {
				t.Fatalf("got %s, want %s: %v", result.Status(), want, result.Error())
			}
		})
	}
	// A directly constructed signature has no raw header, and remains neutral.
	sig.Algorithm = "unsupported"
	sig.Verify(headers, sig.BodyHash, dk)
	if sig.VerifyResult.Status() != VerifyStatusNeutral {
		t.Fatalf("signature without a raw header: %s", sig.VerifyResult.Status())
	}
}
