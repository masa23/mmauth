package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/header"
)

func regressionARCKey(t *testing.T) (ed25519.PrivateKey, *domainkey.DomainKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return key, &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
}
func regressionAddSet(t *testing.T, headers []string, n int, cv ChainValidationResult, key ed25519.PrivateKey) []string {
	t.Helper()
	ams := &ARCMessageSignature{InstanceNumber: n, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := ams.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	headers = append(headers, fmt.Sprintf("ARC-Authentication-Results: i=%d; example.com; dkim=pass\r\n", n), "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: n, Domain: "example.com", Selector: "s", ChainValidation: cv}
	if e := seal.Sign(headers, key); e != nil {
		t.Fatal(e)
	}
	return append(headers, "ARC-Seal: "+seal.String()+"\r\n")
}
func regressionVerify(t *testing.T, headers []string, dk *domainkey.DomainKey) *Signatures {
	t.Helper()
	s, e := ParseARCHeaders(headers)
	if e != nil {
		t.Fatal(e)
	}
	for _, sig := range *s {
		sig.Verify(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", dk)
	}
	return s
}
func TestRegressionEarlierSeal(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	s := regressionVerify(t, headers, dk)
	if s.GetVerifyResult() != VerifyStatusPass {
		t.Fatal("one set baseline failed")
	}
	headers = regressionAddSet(t, headers, 2, ChainValidationResultPass, key)
	s = regressionVerify(t, headers, dk)
	if s.GetInstance(1).VerifyResult.Status() != VerifyStatusPass {
		t.Errorf("unchanged seal i=1 fails after appending i=2: %v", s.GetInstance(1).VerifyResult.Error())
	}
	if s.GetARCChainValidation() != ChainValidationResultPass {
		t.Errorf("valid two-hop chain returns %s", s.GetARCChainValidation())
	}
}
func TestRegressionFailedEarlierSealReportedPass(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	for i, h := range headers {
		if strings.HasPrefix(h, "ARC-Seal:") {
			pos := strings.Index(h, "b=")
			headers[i] = h[:pos] + "b=AAAA\r\n"
		}
	}
	headers = regressionAddSet(t, headers, 2, ChainValidationResultPass, key)
	s := regressionVerify(t, headers, dk)
	if s.GetVerifyResult() == VerifyStatusPass {
		t.Errorf("broken earlier seal reported as %s; chain=%s", s.GetVerifyResultString(), s.GetARCChainValidation())
	}
}
func TestRegressionInvalidCV(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultPass, key)
	s := regressionVerify(t, headers, dk)
	if s.GetARCChainValidation() != ChainValidationResultFail {
		t.Errorf("i=1 cv=pass returns chain=%s", s.GetARCChainValidation())
	}
}
func TestRegressionDuplicateSet(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	headers = append(headers, headers[len(headers)-1])
	s, e := ParseARCHeaders(headers)
	if e != nil {
		return
	}
	for _, sig := range *s {
		sig.Verify(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", dk)
	}
	if s.GetVerifyResult() == VerifyStatusPass {
		t.Error("duplicate ARC-Seal accepted as pass")
	}
}
func TestRegressionUnsignedFrom(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := []string{"Subject: hi\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "s", Algorithm: SignatureAlgorithmED25519_SHA256, Canonicalization: "relaxed/relaxed", Headers: "subject", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := ams.Sign(headers, key); err == nil {
		t.Fatal("signing without From must be rejected")
	}
	// Construct a cryptographically valid but non-compliant AMS without using Sign.
	sig, err := header.SignerWithOmitLastCRLF(append(headers, "ARC-Message-Signature: "+ams.String()+"\r\n"), key, canonical.Relaxed, crypto.SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	ams.Signature = sig
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultNone}
	if err := seal.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n", "From: attacker@example.net\r\n")
	s := regressionVerify(t, headers, dk)
	if s.GetInstance(1).messageResult.Status() != VerifyStatusPermErr || s.GetVerifyResult() != VerifyStatusFail {
		t.Fatal("AMS without From must fail")
	}
}
func TestRegressionHistoricalAMS(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n", "Subject: original\r\n"}, 1, ChainValidationResultNone, key)
	headers[1] = "Subject: modified by mailing list\r\n"
	headers = regressionAddSet(t, headers, 2, ChainValidationResultPass, key)
	s := regressionVerify(t, headers, dk)
	if r := s.GetInstance(1).GetARCSeal().Verify(headers, dk); r.Status() != VerifyStatusPass {
		t.Fatal("old seal must remain valid")
	}
	s.GetInstance(1).Verify(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", dk)
	if s.GetInstance(2).VerifyResult.Status() != VerifyStatusPass {
		t.Fatal("latest set must pass")
	}
	if s.GetARCChainValidation() != ChainValidationResultPass {
		t.Errorf("historical AMS failure invalidates chain: %s", s.GetARCChainValidation())
	}
}
func TestRegressionDifferentKeys(t *testing.T) {
	amsKey, amsDK := regressionARCKey(t)
	sealKey, sealDK := regressionARCKey(t)
	headers := []string{"From: a@example.com\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "ams", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if e := ams.Sign(headers, amsKey); e != nil {
		t.Fatal(e)
	}
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "seal", ChainValidation: ChainValidationResultNone}
	if e := seal.Sign(headers, sealKey); e != nil {
		t.Fatal(e)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")
	s, e := ParseARCHeaders(headers)
	if e != nil {
		t.Fatal(e)
	}
	set := s.GetInstance(1)
	if set.GetARCMessageSignature().Verify(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", amsDK).Status() != VerifyStatusPass || set.GetARCSeal().Verify(headers, sealDK).Status() != VerifyStatusPass {
		t.Fatal("independent signatures must pass")
	}
	set.VerifyWithKeys(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", sealDK, amsDK)
	if set.VerifyResult.Status() != VerifyStatusPass {
		t.Errorf("both signatures individually pass but ARC set fails: %v", set.VerifyResult.Error())
	}
	old := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = old }()
	queries := map[string]int{}
	domainkey.DefaultResolver = func(name string) ([]string, error) {
		queries[name]++
		switch name {
		case "ams._domainkey.example.com":
			return []string{"v=DKIM1; k=ed25519; p=" + amsDK.PublicKey}, nil
		case "seal._domainkey.example.com":
			return []string{"v=DKIM1; k=ed25519; p=" + sealDK.PublicKey}, nil
		default:
			return nil, fmt.Errorf("unexpected lookup %s", name)
		}
	}
	set.Verify(headers, "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M=", nil)
	if s.GetVerifyResult() != VerifyStatusPass || queries["ams._domainkey.example.com"] != 1 || queries["seal._domainkey.example.com"] != 1 {
		t.Fatalf("independent DNS keys: status=%s queries=%v", s.GetVerifyResult(), queries)
	}

}

func TestRegressionARCStructure(t *testing.T) {
	key, _ := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	for _, kind := range []string{"ARC-Seal:", "ARC-Message-Signature:", "ARC-Authentication-Results:"} {
		for i, h := range headers {
			if !strings.HasPrefix(h, kind) {
				continue
			}
			if _, err := ParseARCHeaders(append(append([]string{}, headers...), h)); err == nil {
				t.Errorf("duplicate %s accepted", kind)
			}
			if _, err := ParseARCHeaders(append(append([]string{}, headers[:i]...), headers[i+1:]...)); err == nil {
				t.Errorf("missing %s accepted", kind)
			}
		}
	}
	for _, n := range []string{"0", "2", "51", "999999999"} {
		var invalid []string
		for _, h := range headers {
			invalid = append(invalid, strings.ReplaceAll(h, "i=1", "i="+n))
		}
		if _, err := ParseARCHeaders(invalid); err == nil {
			t.Errorf("instance %s accepted", n)
		}
	}
}
