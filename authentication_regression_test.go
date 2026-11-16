package mmauth

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
)

func TestRegressionMalformedARCStatus(t *testing.T) {
	m := NewMMAuth()
	if _, err := m.Write([]byte("From: a@example.com\r\nARC-Seal: broken\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.Verify()
	if m.AuthenticationHeaders.ARCError == nil {
		t.Fatal("no ARCError")
	}
	if got := m.AuthenticationHeaders.ARCSignatures.GetVerifyResult(); got != arc.VerifyStatusFail {
		t.Fatalf("typed result=%s", got)
	}
	if got := m.AuthenticationHeaders.ARCSignatures.GetVerifyResultString(); got != "arc=fail (malformed ARC headers)" {
		t.Fatalf("string result=%s", got)
	}
	status := m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation()
	if status != arc.ChainValidationResultFail {
		t.Fatalf("ARCError=%v but public chain result=%s", m.AuthenticationHeaders.ARCError, status)
	}
}

func TestRegressionConstructedSignatureBodyHash(t *testing.T) {
	signatures := dkim.Signatures{&dkim.Signature{Algorithm: dkim.SignatureAlgorithmRSA_SHA256, Canonicalization: "relaxed/relaxed", Domain: "example.com", Selector: "s", Version: 1}}
	arcs := arc.Signatures{}
	auth := &AuthenticationHeaders{DKIMSignatures: &signatures, ARCSignatures: &arcs}
	modes := auth.BodyHashCanonAndAlgo()
	if len(modes) != 1 {
		t.Fatalf("constructed signing template produces no body hash modes: got=%v", modes)
	}
}

func TestConstructedTemplateProducesUsableHash(t *testing.T) {
	malformed, err := dkim.ParseDKIMHeaders([]string{"DKIM-Signature: broken\r\n"})
	if err != nil {
		t.Fatal(err)
	}
	if (*malformed)[0].ParseError() == nil {
		t.Fatal("missing parse error")
	}
	template := &dkim.Signature{Algorithm: dkim.SignatureAlgorithmRSA_SHA256, Canonicalization: "relaxed/relaxed"}
	sigs := append(*malformed, template)
	arcs := arc.Signatures{}
	a := &AuthenticationHeaders{DKIMSignatures: &sigs, ARCSignatures: &arcs}
	modes := a.BodyHashCanonAndAlgo()
	if len(modes) != 1 || modes[0].Body != CanonicalizationRelaxed || modes[0].Algorithm != crypto.SHA256 {
		t.Fatalf("modes=%v", modes)
	}
	m := NewMMAuth()
	for _, mode := range modes {
		m.AddBodyHash(mode)
	}
	if _, err := m.Write([]byte("From: a@example.com\r\n\r\nbody \t\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("body\r\n"))
	if got := m.GetBodyHash(modes[0]); got != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("wrong template hash: %s", got)
	}
}
