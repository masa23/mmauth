package arc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/masa23/mmauth/internal/canonical"
)

func TestRegressionSealFailedChain(t *testing.T) {
	key, _ := regressionARCKey(t)
	prior := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	cases := map[string][]string{
		"complete":      prior,
		"missing seal":  prior[:len(prior)-1],
		"malformed AMS": {"From: a@example.com\r\n", "ARC-Message-Signature: i=1; c=invalid/invalid\r\n"},
		"unparseable":   {"From: a@example.com\r\n", "ARC-Seal: broken\r\n"},
	}
	for _, kind := range []string{"ARC-Seal:", "ARC-Message-Signature:", "ARC-Authentication-Results:"} {
		for _, raw := range prior {
			if strings.HasPrefix(raw, kind) {
				cases["duplicate "+kind] = append(append([]string{}, prior...), raw)
			}
		}
	}
	for name, old := range cases {
		t.Run(name, func(t *testing.T) {
			ams := &ARCMessageSignature{InstanceNumber: 2, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
			if err := ams.Sign(old, key); err != nil {
				t.Fatal(err)
			}
			current := []string{"ARC-Authentication-Results: i=2; example.com; arc=fail\r\n", "ARC-Message-Signature: " + ams.String() + "\r\n"}
			headers := append(append([]string{}, old...), current...)
			seal := &ARCSeal{InstanceNumber: 2, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultFail}
			if err := seal.Sign(headers, key); err != nil {
				t.Fatalf("cv=fail signing: %v", err)
			}
			// Check the signature independently over exactly the new set. Historical
			// headers must not contribute, even when they were structurally valid.
			expected := canonical.RelaxedHeader(current[0]) + canonical.RelaxedHeader(current[1]) + strings.TrimSuffix(canonical.RelaxedHeader("ARC-Seal: "+seal.StringWithoutSignature()+"\r\n"), "\r\n")
			digest := sha256.Sum256([]byte(expected))
			signature, err := base64.StdEncoding.DecodeString(seal.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), digest[:], signature) {
				t.Fatal("seal did not sign exactly the new set")
			}
			// Failure sealing still rejects duplicate or missing headers in its own set.
			if err := seal.Sign(append(headers, current[0]), key); err == nil {
				t.Fatal("duplicate current AAR accepted")
			}
			if err := seal.Sign(append(append([]string{}, old...), current[1]), key); err == nil {
				t.Fatal("missing current AAR accepted")
			}
		})
	}
	// Normal sealing must still reject a duplicated historical header.
	seal := &ARCSeal{InstanceNumber: 2, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultPass}
	if err := seal.Sign(append(append([]string{}, prior...), prior[len(prior)-1]), key); err == nil {
		t.Fatal("cv=pass accepted duplicated history")
	}
}

func TestFailedARCParseResults(t *testing.T) {
	for _, tc := range []struct {
		input []string
		max   int
	}{
		{[]string{"ARC-Seal: broken\r\n"}, 0},
		{[]string{"ARC-Seal: i=1;\r\n", "ARC-Seal: i=1;\r\n", "ARC-Message-Signature: i=7; c=invalid/invalid\r\n"}, 7},
		{[]string{"ARC-Seal: i=999999999;\r\n"}, 0},
	} {
		sigs, err := ParseARCHeaders(tc.input)
		if err == nil || sigs == nil {
			t.Fatalf("expected failure state and error: %v, %v", sigs, err)
		}
		for _, s := range *sigs {
			s.Verify(tc.input, "", nil) // must retain the parse failure without DNS
			if s.VerifyResult.Status() != VerifyStatusFail || s.VerifyResult.Error() != err {
				t.Fatal("parse error lost during verification")
			}
		}
		if sigs.GetMaxInstance() != tc.max || sigs.GetVerifyResult() != VerifyStatusFail || sigs.GetARCChainValidation() != ChainValidationResultFail || sigs.GetVerifyResultString() != "arc=fail (malformed ARC headers)" {
			t.Fatalf("inconsistent failure state: %v", sigs)
		}
	}
	empty, err := ParseARCHeaders([]string{"From: a@example.com\r\n"})
	if err != nil || empty.GetVerifyResult() != VerifyStatusNone {
		t.Fatal("absent ARC must still be none")
	}
}
