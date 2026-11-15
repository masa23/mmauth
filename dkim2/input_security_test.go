package dkim2

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestUnfoldLinearAllocations(t *testing.T) {
	raw := "Subject: start" + strings.Repeat("\r\n x", 16000) + "\r\n"
	want := "Subject: start" + strings.Repeat(" x", 16000)
	if got, err := unfold(raw); err != nil || got != want {
		t.Fatalf("unfold: len=%d err=%v", len(got), err)
	}
	// Rebuilding the whole field at each fold uses one allocation per fold.
	if allocations := testing.AllocsPerRun(5, func() { _, _ = unfold(raw) }); allocations > 2 {
		t.Fatalf("allocations per field = %v, want <= 2", allocations)
	}
	for _, raw := range []string{"Subject: x\r\ny\r\n", "Subject: x\ny\r\n", "Subject: x\r", "Subject: x\r\n\r\n"} {
		if _, err := unfold(raw); err == nil {
			t.Fatalf("accepted invalid fold %q", raw)
		}
	}
}

func TestParseResourceLimits(t *testing.T) {
	field := func(size int) string { return "X:" + strings.Repeat("a", size-4) + "\r\n" }
	tests := []struct {
		name      string
		wire      string
		wantError string
	}{
		{"field boundary", field(maxHeaderFieldBytes), ""},
		{"long field", field(maxHeaderFieldBytes + 1), "header field exceeds"},
		{"long folded field", "X:" + strings.Repeat("\r\n a", maxHeaderFieldBytes/4) + "\r\n", "header field exceeds"},
		{"header boundary", strings.Repeat(field(maxHeaderFieldBytes), maxHeaderBytes/maxHeaderFieldBytes), ""},
		{"large headers", strings.Repeat(field(maxHeaderFieldBytes), maxHeaderBytes/maxHeaderFieldBytes) + "X:a\r\n", "headers exceed"},
		{"count boundary", strings.Repeat("X:a\r\n", maxHeaderFields), ""},
		{"many fields", strings.Repeat("X:a\r\n", maxHeaderFields+1), "header count exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.wire))
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %s", err, test.wantError)
			}
		})
	}
	wire := make([]byte, maxMessageBytes+1)
	if _, err := Parse(wire); err == nil || !strings.Contains(err.Error(), "message exceeds") {
		t.Fatalf("large message error = %v", err)
	}
}

func TestSignatureLimitsBeforeDecoding(t *testing.T) {
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	old := "ed25519-sha256:" + foldBase64(m.Signatures[0].Values[0].Value)
	for _, test := range []struct {
		algorithm string
		size      int
	}{
		{"rsa-sha256", maxRSASignatureBytes},
		{"ed25519-sha256", ed25519.SignatureSize},
		{"mldsa44", mldsa44.SignatureSize},
	} {
		t.Run(test.algorithm, func(t *testing.T) {
			value := base64.StdEncoding.EncodeToString(make([]byte, test.size+1))
			bad := bytes.Replace(wire, []byte(old), []byte(test.algorithm+":"+value), 1)
			if _, err := Parse(bad); err == nil {
				t.Fatal("oversized signature accepted")
			}
		})
	}
}

func TestIDNASecurityValidation(t *testing.T) {
	for _, domain := range []string{
		"xn--example-.com", "XN--EXAMPLE-.COM", "xn--a-.example",
		"ｘｎ--example-.com", "xn\u00ad--example-.com", "xn--example-\u00ad.com",
		"example\xff.com", "\xc0\xaf.example",
	} {
		t.Run(domain, func(t *testing.T) {
			if got, err := asciiDomain(domain); err == nil {
				t.Fatalf("invalid domain %q mapped to %q", domain, got)
			}
			env := Envelope{"<alice@" + domain + ">", []string{"<bob@relay.test>"}}
			if _, err := normalizeEnvelope(env); err == nil {
				t.Fatal("invalid envelope accepted")
			}
			if _, err := fromDomain([]string{"From: alice@" + domain + "\r\n"}); err == nil {
				t.Fatal("invalid From accepted")
			}
		})
	}
	for domain, want := range map[string]string{
		"EXAMPLE.COM": "example.com", "例え.テスト": "xn--r8jz45g.xn--zckzah",
		"BÜCHER.example": "xn--bcher-kva.example", "XN--BCHER-KVA.example": "xn--bcher-kva.example",
	} {
		if got, err := asciiDomain(domain); err != nil || got != want {
			t.Fatalf("asciiDomain(%q) = %q, %v; want %q", domain, got, err, want)
		}
	}
}

func FuzzParseDKIM2(f *testing.F) {
	f.Add([]byte("From: alice@example.com\r\n\r\nbody\r\n"))
	f.Add([]byte("Message-Instance: m=1;\r\n h=sha256:AA==:AA==;\r\n\r\n"))
	f.Add([]byte("DKIM2-Signature: i=1; m=1; t=0; d=example.com; s=bad;\r\n\r\n"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = Parse(wire)
	})
}
