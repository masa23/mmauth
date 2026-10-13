package mmauth

import (
	"testing"

	"github.com/masa23/mmauth/dkim"
)

func TestRFC8301HistoricDKIMSkipsSHA1BodyHash(t *testing.T) {
	const message = "DKIM-Signature: v=1; a=rsa-sha1; c=simple/simple; d=example.com; s=s; h=From; bh=uoq1oCgLlTqpdDX/iUbLy7J1Wic=; b=AA==\r\n" +
		"From: a@example.com\r\n\r\nbody\r\n"
	m := NewMMAuth()
	if _, err := m.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if modes := m.AuthenticationHeaders.BodyHashCanonAndAlgo(); len(modes) != 0 {
		t.Fatalf("historic signature requested body hash: %+v", modes)
	}
	m.Verify()
	sigs := *m.AuthenticationHeaders.DKIMSignatures
	if len(sigs) != 1 || sigs[0].VerifyResult.Status() != dkim.VerifyStatusPermErr {
		t.Fatalf("historic signature not rejected: %+v", sigs)
	}
}
