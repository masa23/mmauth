package mmauth

import (
	"strings"
	"testing"

	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
)

func TestRFC8301HistoricARCSkipsSHA1BodyHash(t *testing.T) {
	key, _ := arcTestKey()
	fields := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	for i, field := range fields {
		if strings.HasPrefix(field, "ARC-Message-Signature:") {
			fields[i] = strings.Replace(field, "a=ed25519-sha256", "a=rsa-sha1", 1)
		}
	}
	m := NewMMAuth()
	if _, err := m.Write([]byte(strings.Join(fields, "") + "\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if m.AuthenticationHeaders.ARCError != nil {
		t.Fatalf("historic ARC signature was not parsed: %v", m.AuthenticationHeaders.ARCError)
	}
	if modes := m.AuthenticationHeaders.BodyHashCanonAndAlgo(); len(modes) != 0 || len(m.bodyHashed) != 0 {
		t.Fatalf("historic ARC signature requested body hash: %+v, computed=%+v", modes, m.bodyHashed)
	}
	ams := m.AuthenticationHeaders.ARCSignatures.GetInstance(1).GetARCMessageSignature()
	if result := ams.Verify(m.Headers, "", nil); result.Status() != arc.VerifyStatusPermErr {
		t.Fatalf("historic ARC signature not rejected: %s", result.Status())
	}
}

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
