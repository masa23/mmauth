package arc

import (
	"crypto"
	"strings"
	"testing"

	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/header"
)

func TestARCSealMissingCV(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	last := len(headers) - 1
	// Sign an actual header without cv so that cryptographic failure cannot hide
	// a missing structural check.
	raw := strings.Replace(headers[last], "cv=none;", "", 1)
	raw = raw[:strings.Index(raw, "b=")+2]
	signed, err := header.SignerWithOmitLastCRLF([]string{headers[1], headers[2], raw + "\r\n"}, key, canonical.Relaxed, crypto.SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	headers[last] = raw + signed + "\r\n"
	if _, err := ParseARCSeal(headers[last]); err == nil {
		t.Fatal("missing cv accepted")
	}
	sigs, err := ParseARCHeaders(headers)
	if err == nil || sigs.GetVerifyResult() != VerifyStatusFail {
		t.Fatalf("missing cv: err=%v chain=%s", err, sigs.GetVerifyResult())
	}
	// Manually constructed seals must also fail before DNS lookup.
	seal := &ARCSeal{InstanceNumber: 1, Algorithm: SignatureAlgorithmED25519_SHA256, Domain: "example.com", Selector: "s", Signature: signed, raw: headers[last], hashAlgo: crypto.SHA256}
	if result := seal.Verify(headers, dk); result.Status() != VerifyStatusFail {
		t.Fatalf("standalone seal=%s", result.Status())
	}
	for _, cv := range []string{"", "bogus"} {
		seal.ChainValidation = ChainValidationResult(cv)
		if result := seal.Verify(nil, nil); result.Status() != VerifyStatusFail {
			t.Fatalf("cv=%q status=%s", cv, result.Status())
		}
	}
	// Forbidden tags cannot substitute for an explicit cv tag.
	if _, err := ParseARCSeal(strings.Replace(headers[last], "i=1;", "i=1; h=from;", 1)); err == nil {
		t.Fatal("forbidden tag concealed missing cv")
	}
}
