package mmauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/spf"
)

func TestHeaderOnlyDKIMVerification(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
	headers := []string{"From: a@example.com\r\n", "Subject: header-only message\r\n"}
	for _, mode := range []Canonicalization{CanonicalizationSimple, CanonicalizationRelaxed} {
		t.Run(string(mode), func(t *testing.T) {
			body := ""
			if mode == CanonicalizationSimple {
				body = crlf
			}
			sum := sha256.Sum256([]byte(body))
			want := base64.StdEncoding.EncodeToString(sum[:])
			sig := &dkim.Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: string(mode) + "/" + string(mode), BodyHash: want}
			if err := sig.Sign(headers, key); err != nil {
				t.Fatal(err)
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte("DKIM-Signature: " + sig.String() + crlf + strings.Join(headers, ""))); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatalf("header-only message rejected: %v", err)
			}
			got := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{Body: mode, Algorithm: crypto.SHA256})
			if got != want {
				t.Fatalf("empty body hash=%q, want %q", got, want)
			}
			sigs := *m.AuthenticationHeaders.DKIMSignatures
			if len(sigs) != 1 {
				t.Fatalf("DKIM signatures=%d, want 1", len(sigs))
			}
			sigs[0].Verify(m.Headers, got, dk)
			if sigs[0].VerifyResult.Status() != dkim.VerifyStatusPass {
				t.Fatalf("DKIM verification failed: %v", sigs[0].VerifyResult.Error())
			}
		})
	}
}

func TestRegressionSPFIdentity(t *testing.T) {
	old := spf.DefaultTXTResolver
	defer func() { spf.DefaultTXTResolver = old }()
	spf.DefaultTXTResolver = func(name string) ([]string, error) {
		if name == "helo.example.net" {
			return []string{"v=spf1 +all"}, nil
		}
		return []string{"v=spf1 -all"}, nil
	}
	m := NewMMAuth()
	_, err := m.Write([]byte("From: victim@example.com\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), "helo.example.net", "victim@example.com")
	t.Logf("authentication results: %v", got)
	if !strings.Contains(got[0], "spf=fail smtp.mailfrom=victim@example.com") {
		t.Error("HELO pass attributed to unauthorized MAIL FROM")
	}
}

func TestRegressionZeroBodyLength(t *testing.T) {
	empty := sha256.Sum256(nil)
	want := base64.StdEncoding.EncodeToString(empty[:])
	m := NewMMAuth()
	_, err := m.Write([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s; h=from; l=0; bh=" + want + "; b=AA==\r\nFrom: x@example.com\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	got := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{Body: CanonicalizationSimple, Algorithm: crypto.SHA256, Limit: 0, LimitSet: true})
	if got != want {
		t.Errorf("l=0: hash=%s want empty hash=%s", got, want)
	}
}

func TestRegressionBodyBufferAmplification(t *testing.T) {
	var modes []BodyCanonicalizationAndAlgorithm
	for i := 1; i <= 32; i++ {
		modes = append(modes, BodyCanonicalizationAndAlgorithm{Body: CanonicalizationSimple, Algorithm: crypto.SHA256, Limit: int64(i)})
	}
	mh := &multiBodyHash{}
	mh.bodyHash(modes)
	// Exercise a long line with many length limits. Each hash must cover only
	// its requested prefix, and all limits share one canonicalization stream.
	payload := []byte(strings.Repeat("x", 1<<20))
	if _, err := mh.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := mh.Close(); err != nil {
		t.Fatal(err)
	}
	if len(mh.canonicalizers) != 1 {
		t.Fatalf("canonicalizers = %d, want 1", len(mh.canonicalizers))
	}
	for i, got := range mh.Get() {
		h := sha256.Sum256(payload[:i+1])
		if got.BodyHash != base64.StdEncoding.EncodeToString(h[:]) {
			t.Errorf("wrong hash for l=%d", i+1)
		}
	}
}

func TestBodyLengthPresence(t *testing.T) {
	m := NewMMAuth()
	for _, mode := range []Canonicalization{CanonicalizationSimple, CanonicalizationRelaxed} {
		for _, limit := range []int64{0, 1, 4, 99} {
			for _, specified := range []bool{false, true} {
				m.AddBodyHash(BodyCanonicalizationAndAlgorithm{Body: mode, Algorithm: crypto.SHA256, Limit: limit, LimitSet: specified})
			}
		}
	}
	if _, err := m.Write([]byte("From: a@example.com\r\n\r\na \t\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []Canonicalization{CanonicalizationSimple, CanonicalizationRelaxed} {
		body := "a \t\r\n"
		if mode == CanonicalizationRelaxed {
			body = "a\r\n"
		}
		for _, limit := range []int64{0, 1, 4, 99} {
			for _, specified := range []bool{false, true} {
				expected := body
				if (limit > 0 || specified) && limit < int64(len(expected)) {
					expected = expected[:limit]
				}
				sum := sha256.Sum256([]byte(expected))
				want := base64.StdEncoding.EncodeToString(sum[:])
				got := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{Body: mode, Algorithm: crypto.SHA256, Limit: limit, LimitSet: specified})
				if got != want {
					t.Errorf("mode=%s limit=%d specified=%v: %s != %s", mode, limit, specified, got, want)
				}
			}
		}
	}
}

func TestNullReversePathSPF(t *testing.T) {
	old := spf.DefaultTXTResolver
	defer func() { spf.DefaultTXTResolver = old }()
	spf.DefaultTXTResolver = func(name string) ([]string, error) {
		if name != "helo.example.net" {
			t.Errorf("unexpected lookup %q", name)
		}
		return []string{"v=spf1 +all"}, nil
	}
	for _, from := range []string{"", "<>"} {
		m := NewMMAuth()
		if _, err := m.Write([]byte("From: a@example.com\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), "helo.example.net", from)
		if got[0] != "spf=pass smtp.helo=helo.example.net" {
			t.Errorf("null sender %q: %s", from, got[0])
		}
	}
}

func TestMalformedAuthenticationIsolation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
	headers := []string{"From: a@example.com\r\n"}
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	sig := &dkim.Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: bh}
	if err := sig.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	ams := &arc.ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: bh}
	if err := ams.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "DKIM-Signature: broken\r\n", "DKIM-Signature: "+sig.String()+"\r\n", "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &arc.ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "s", ChainValidation: arc.ChainValidationResultNone}
	if err := seal.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")
	old := spf.DefaultTXTResolver
	defer func() { spf.DefaultTXTResolver = old }()
	spf.DefaultTXTResolver = func(string) ([]string, error) { return nil, nil }
	for _, brokenARC := range []bool{false, true} {
		input := strings.Join(headers, "")
		if brokenARC {
			input += "ARC-Seal: broken\r\n"
		}
		m := NewMMAuth()
		if _, err := m.Write([]byte(input + "\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		gotBH := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{Body: CanonicalizationRelaxed, Algorithm: crypto.SHA256})
		if gotBH != bh {
			t.Fatalf("body hash lost: %q", gotBH)
		}
		for _, d := range *m.AuthenticationHeaders.DKIMSignatures {
			d.Verify(m.Headers, gotBH, dk)
		}
		if d := (*m.AuthenticationHeaders.DKIMSignatures)[1]; d.VerifyResult.Status() != dkim.VerifyStatusPass {
			t.Fatal(d.VerifyResult.Error())
		}
		if brokenARC {
			if m.AuthenticationHeaders.ARCError == nil {
				t.Fatal("missing ARC parse error")
			}
		} else {
			if m.AuthenticationHeaders.ARCError != nil {
				t.Fatal(m.AuthenticationHeaders.ARCError)
			}
			for _, a := range *m.AuthenticationHeaders.ARCSignatures {
				a.Verify(m.Headers, gotBH, dk)
			}
			if m.AuthenticationHeaders.ARCSignatures.GetVerifyResult() != arc.VerifyStatusPass {
				t.Fatal("malformed DKIM must not prevent ARC pass")
			}
		}
		results := strings.Join(m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), "example.com", "a@example.com"), "; ")
		wantARC := "arc=pass"
		if brokenARC {
			wantARC = "arc=fail"
		}
		if !strings.Contains(results, "dkim=pass") || !strings.Contains(results, "dkim=permerror") || !strings.Contains(results, wantARC) {
			t.Fatalf("lost independent results: %s", results)
		}
	}
}
