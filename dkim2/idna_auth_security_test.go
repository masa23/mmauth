package dkim2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Reproduce a remote signer claiming that a different Unicode From domain is
// authentic. Construct the signatures directly so Sign's validation cannot
// hide a defect in Verify.
func TestIDNAFromCannotCollapseIntoSigningDomain(t *testing.T) {
	key := edKey()
	for _, domain := range []string{"İ.example", "I\u0307.example", "i\u0307.example"} {
		t.Run(domain, func(t *testing.T) {
			env := Envelope{"<alice@i.example>", []string{"<bob@example.net>"}}
			message := []byte("From: alice@" + domain + "\r\n\r\nbody\r\n")
			options := SignOptions{Domain: "i.example", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime}
			if _, err := Sign(message, options); err == nil {
				t.Fatal("signed From of a different or invalid IDNA domain")
			}
			m, err := Parse(message)
			if err != nil {
				t.Fatal(err)
			}
			hh, _ := headerDigest(m.Headers, "sha256")
			bh, _ := bodyDigest(m.Body, "sha256")
			mi := fmt.Sprintf("Message-Instance: m=1; h=sha256:%s:%s;\r\n", hh, bh)
			sig, err := makeSignature([]Instance{{Number: 1, Raw: mi}}, nil, 1, options)
			if err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(sig+mi), message...)
			result := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.i.example": {keyRecord(key)}}, Now: testTime})
			if result.Status != Fail || result.ReplayID != "" {
				t.Fatalf("foreign From authenticated: %+v", result)
			}
		})
	}
}

func TestIDNAEnvelopeCannotCollapseIntoASCII(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@i.example>", []string{"<bob@i.example>"}}
	message := []byte("From: alice@i.example\r\n\r\nbody\r\n")
	wire, err := Sign(message, SignOptions{Domain: "i.example", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, actual := range []Envelope{
		{"<alice@İ.example>", env.RcptTo},
		{env.MailFrom, []string{"<bob@İ.example>"}},
		{"<alice@i\u0307.example>", env.RcptTo},
		{env.MailFrom, []string{"<bob@i\u0307.example>"}},
	} {
		result := Verify(wire, actual, VerifyOptions{Resolver: records{"s1._domainkey.i.example": {keyRecord(key)}}, Now: testTime})
		if result.Status != Fail {
			t.Fatalf("foreign envelope authenticated: %+v", result)
		}
	}
}

func TestPostmasterRejectsUnicodeFolding(t *testing.T) {
	path := "<Poſtmaster>" // U+017F folds to ASCII s under EqualFold.
	if validPath(path, false) {
		t.Fatal("Unicode lookalike accepted as reserved ASCII mailbox")
	}
	if _, err := normalizePath(path); err == nil {
		t.Fatal("Unicode lookalike normalized as reserved ASCII mailbox")
	}
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<Postmaster>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	env.RcptTo = []string{path}
	result := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime})
	if result.Status != Fail {
		t.Fatalf("Unicode lookalike delivery authenticated: %+v", result)
	}
}

// A valid U-label and its own A-label remain equivalent, including when a
// remote signer puts the U-label directly in the From field.
func TestIDNACombiningDotRetainsDomainIdentity(t *testing.T) {
	key := edKey()
	const domain = "xn--i-9bb.example"
	env := Envelope{"<alice@i\u0307.example>", []string{"<bob@i\u0307.example>"}}
	message := []byte("From: alice@i\u0307.example\r\n\r\nbody\r\n")
	wire, err := Sign(message, SignOptions{Domain: domain, Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, actual := range []Envelope{env, {"<alice@" + domain + ">", []string{"<bob@" + domain + ">"}}} {
		result := Verify(wire, actual, VerifyOptions{Resolver: records{"s1._domainkey." + domain: {keyRecord(key)}}, Now: testTime})
		if result.Status != Pass {
			t.Fatalf("valid IDNA domain rejected: %+v", result)
		}
	}
}

// Also exercise From validation with an Ed25519 signature independently
// calculated from the message hashes, matching the external attack surface.
func TestIDNAForgedFromWithIndependentSignature(t *testing.T) {
	key := edKey()
	enc := base64.StdEncoding.EncodeToString
	hh := sha256.Sum256([]byte("from:alice@İ.example\r\n"))
	bh := sha256.Sum256([]byte("body\r\n"))
	mi := "message-instance:m=1;h=sha256:" + enc(hh[:]) + ":" + enc(bh[:]) + ";\r\n"
	sig := fmt.Sprintf("dkim2-signature:i=1;m=1;t=%d;mf=%s;rt=%s;d=i.example;s=s1:ed25519-sha256:;\r\n", testTime.Unix(), enc([]byte("<alice@i.example>")), enc([]byte("<bob@example.net>")))
	hash := sha256.Sum256([]byte(mi + sig))
	sig = strings.Replace(sig, "ed25519-sha256:", "ed25519-sha256:"+enc(ed25519.Sign(key, hash[:])), 1)
	wire := []byte(sig + mi + "From: alice@İ.example\r\n\r\nbody\r\n")
	result := Verify(wire, Envelope{"<alice@i.example>", []string{"<bob@example.net>"}}, VerifyOptions{Resolver: records{"s1._domainkey.i.example": {keyRecord(key)}}, Now: testTime})
	if result.Status != Fail {
		t.Fatalf("independently signed foreign From authenticated: %+v", result)
	}
}

func FuzzIDNADomainIdentity(f *testing.F) {
	for _, domain := range []string{"İ.example", "i\u0307.example", "bücher.EXAMPLE", "例え.テスト", "xn--example-.com", "XN--BCHER-KVA.example", "\xff.example"} {
		f.Add(domain)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		ascii, err := asciiDomain(domain)
		if err != nil {
			return
		}
		if !validDomain(ascii) {
			t.Fatalf("invalid output domain %q", ascii)
		}
		if second, err := asciiDomain(ascii); err != nil || second != ascii {
			t.Fatalf("non-idempotent A-label: %q -> %q (%v)", ascii, second, err)
		}
		before, after := strings.Split(domain, "."), strings.Split(ascii, ".")
		if len(before) != len(after) {
			t.Fatal("domain conversion changed label count")
		}
		for i, label := range before {
			nonASCII := false
			for j := 0; j < len(label); j++ {
				nonASCII = nonASCII || label[j] >= 128
			}
			if nonASCII {
				u, err := smtpIDNA.ToUnicode(after[i])
				if err != nil || u != label {
					t.Fatalf("U-label identity lost: %q -> %q -> %q (%v)", label, after[i], u, err)
				}
			}
		}
	})
}
