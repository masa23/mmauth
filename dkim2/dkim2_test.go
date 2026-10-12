package dkim2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strconv"
	"testing"
	"time"
)

type records map[string][]string

func (r records) LookupTXT(_ context.Context, name string) ([]string, error) {
	v, ok := r[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true, Name: name}
	}
	return v, nil
}

type dnsFailure struct{}

func (dnsFailure) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsTemporary: true}
}

var testTime = time.Unix(1780000000, 0)

func edKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) }

func keyRecord(key crypto.Signer) string {
	switch pub := key.Public().(type) {
	case ed25519.PublicKey:
		return "v=DKIM1; k=ed25519; h=sha1; p=" + base64.StdEncoding.EncodeToString(pub)
	case *rsa.PublicKey:
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	default:
		panic("unexpected key")
	}
}

func original() []byte {
	return []byte("From: Alice <alice@example.com>\r\nSubject: original\r\nReceived: ignored\r\n\r\nhello\r\n")
}

func TestSignVerifyAndMutation(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	for _, hash := range []string{"sha256", "sha512"} {
		t.Run(hash, func(t *testing.T) {
			wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime, HashAlgorithm: hash})
			if err != nil {
				t.Fatal(err)
			}
			resolver := records{"s1._domainkey.example.com": {keyRecord(key)}}
			options := VerifyOptions{Resolver: resolver, Now: testTime.Add(time.Hour)}
			if r := Verify(wire, env, options); r.Status != Pass {
				t.Fatalf("verify=%s: %v", r.Status, r.Err)
			}
			changed := bytes.Replace(wire, []byte("Subject: original"), []byte("Subject: changed"), 1)
			if r := Verify(changed, env, options); r.Status != Fail {
				t.Fatalf("header mutation=%s: %v", r.Status, r.Err)
			}
			changed = bytes.Replace(wire, []byte("hello\r\n"), []byte("changed\r\n"), 1)
			if r := Verify(changed, env, options); r.Status != Fail {
				t.Fatalf("body mutation=%s: %v", r.Status, r.Err)
			}
			changed = bytes.Replace(wire, []byte("Received: ignored"), []byte("Received: changed"), 1)
			if r := Verify(changed, env, options); r.Status != Pass {
				t.Fatalf("unsigned trace mutation=%s: %v", r.Status, r.Err)
			}
			wrong := Envelope{"<alice@example.com>", []string{"<eve@relay.test>"}}
			if r := Verify(wire, wrong, options); r.Status != PermError {
				t.Fatalf("envelope mismatch=%s: %v", r.Status, r.Err)
			}
			resolver["s1._domainkey.example.com"] = []string{keyRecord(key), keyRecord(key)}
			if r := Verify(wire, env, options); r.Status != PermError {
				t.Fatalf("multiple TXT records=%s: %v", r.Status, r.Err)
			}
		})
	}
}

func TestForwardAndRevise(t *testing.T) {
	first := edKey()
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	resolver := records{
		"s1._domainkey.example.com": {keyRecord(first)},
		"s2._domainkey.relay.test":  {keyRecord(second)},
	}
	options := VerifyOptions{Resolver: resolver, Now: testTime.Add(time.Hour)}
	initial, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: first, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := Forward(initial, SignOptions{Domain: "relay.test", Selector: "s2", Key: second, Envelope: out, Timestamp: testTime.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(forwarded, out, options); r.Status != Pass {
		t.Fatalf("forwarded=%s: %v", r.Status, r.Err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&second.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver["s2._domainkey.relay.test"] = []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(spki)}
	if r := Verify(forwarded, out, options); r.Status != PermError {
		t.Fatalf("SPKI DKIM2 key=%s: %v", r.Status, r.Err)
	}
	resolver["s2._domainkey.relay.test"] = []string{keyRecord(second)}
	modified := bytes.Replace(initial, []byte("Subject: original"), []byte("Subject: revised"), 1)
	modified = append(modified, []byte("footer\r\n")...)
	recipe := []byte(`{"h":{"subject":[{"d":[" original"]}]},"b":[{"c":[1,1]}]}`)
	revised, err := Revise(modified, recipe, SignOptions{Domain: "relay.test", Selector: "s2", Key: second, Envelope: out, Timestamp: testTime.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(revised, out, options); r.Status != Pass {
		t.Fatalf("revised=%s: %v", r.Status, r.Err)
	}
	thirdEnvelope := Envelope{"<bounce@example.net>", []string{"<dest@example.net>"}}
	resolver["s3._domainkey.example.net"] = []string{keyRecord(first)}
	modifiedAgain := append(append([]byte(nil), revised...), []byte("footer2\r\n")...)
	twice, err := Revise(modifiedAgain, []byte(`{"b":[{"c":[1,2]}]}`), SignOptions{Domain: "example.net", Selector: "s3", Key: first, Envelope: thirdEnvelope, Timestamp: testTime.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(twice, thirdEnvelope, options); r.Status != Pass {
		t.Fatalf("two revisions=%s: %v", r.Status, r.Err)
	}
	broken := bytes.Replace(revised, []byte("footer\r\n"), []byte("altered\r\n"), 1)
	if r := Verify(broken, out, options); r.Status != Fail {
		t.Fatalf("revised mutation=%s: %v", r.Status, r.Err)
	}
	if _, err := Revise(modified, []byte(`{"b":null}`), SignOptions{Domain: "relay.test", Selector: "s2", Key: second, Envelope: out, Timestamp: testTime}); err == nil {
		t.Fatal("null Recipe signed without validating previous content")
	}
	if _, err := Forward(initial, SignOptions{Domain: "other.test", Selector: "s2", Key: second, Envelope: out, Timestamp: testTime}); err == nil {
		t.Fatal("broken custody accepted")
	}
}

func TestMalformedFieldsAndDNSErrors(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{Resolver: records{}, Now: testTime}
	if r := Verify(wire, env, options); r.Status != PermError {
		t.Fatalf("missing key=%s: %v", r.Status, r.Err)
	}
	if r := Verify(wire, env, VerifyOptions{Resolver: dnsFailure{}, Now: testTime}); r.Status != TempError {
		t.Fatalf("temporary DNS=%s: %v", r.Status, r.Err)
	}
	testingRecords := records{"s1._domainkey.example.com": {keyRecord(key) + "; t=y"}}
	if r := Verify(wire, env, VerifyOptions{Resolver: testingRecords, Now: testTime}); r.Status != Pass {
		t.Fatalf("valid testing key=%s: %v", r.Status, r.Err)
	}
	changed := bytes.Replace(wire, []byte("hello\r\n"), []byte("tampered\r\n"), 1)
	if r := Verify(changed, env, VerifyOptions{Resolver: testingRecords, Now: testTime}); r.Status != None {
		t.Fatalf("testing key mismatch=%s: %v", r.Status, r.Err)
	}
	malformed := bytes.Replace(wire, []byte("m=1;"), []byte("m=1; m=2;"), 1)
	if r := Verify(malformed, env, options); r.Status != PermError {
		t.Fatalf("duplicate tag=%s: %v", r.Status, r.Err)
	}
	malformed = bytes.Replace(wire, []byte("s=s1:"), []byte("s=s1:bogus:"), 1)
	if r := Verify(malformed, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}); r.Status != PermError {
		t.Fatalf("unknown only signature=%s: %v", r.Status, r.Err)
	}
	if _, err := Parse([]byte("From: a\n\nbody")); err == nil {
		t.Fatal("bare LF accepted")
	}
	if _, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s", Key: key, Envelope: Envelope{"<alice@evil.test>", env.RcptTo}}); err == nil {
		t.Fatal("unmatched domain signed")
	}
	if _, err := Revise(wire, []byte(`{"b":[{"c":[2,1]}]}`), SignOptions{Domain: "relay.test", Selector: "s", Key: key, Envelope: Envelope{"<bounce@relay.test>", []string{"<x@example.net>"}}}); err == nil {
		t.Fatal("invalid Recipe accepted")
	}
}

// This fixture builds the digest and signature without using Sign,
// headerDigest, bodyDigest, signatureInput, or the package's serialization.
func TestIndependentWireSignatureWithFirstSTag(t *testing.T) {
	key := edKey()
	body := []byte("hello\r\n")
	hh := sha256.Sum256([]byte("from:Alice <alice@example.com>\r\nsubject:original\r\n"))
	bh := sha256.Sum256(body)
	mi := "Message-Instance: m=1; h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n"
	mf := base64.StdEncoding.EncodeToString([]byte("<alice@example.com>"))
	rt := base64.StdEncoding.EncodeToString([]byte("<bob@relay.test>"))
	stamp := strconv.FormatInt(testTime.Unix(), 10)
	sigPrefix := "S=s1:ed25519-sha256:;i=1;m=1;t=" + stamp + ";mf=" + mf + ";rt=" + rt + ";d=example.com;"
	input := "message-instance:m=1;h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n" +
		"dkim2-signature:" + sigPrefix + "\r\n"
	digest := sha256.Sum256([]byte(input))
	signed := base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest[:]))
	sig := "DKIM2-Signature: S=s1:ed25519-sha256:" + signed + "; i=1; m=1; t=" + stamp + "; mf=" + mf + "; rt=" + rt + "; d=example.com;\r\n"
	wire := append([]byte(sig+mi), original()...)
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	result := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime})
	if result.Status != Pass {
		t.Fatalf("independent signature=%s: %v", result.Status, result.Err)
	}
}

func TestMultipleSignaturesAllChecked(t *testing.T) {
	ed := edKey()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	hh := sha256.Sum256([]byte("from:Alice <alice@example.com>\r\nsubject:original\r\n"))
	bh := sha256.Sum256([]byte("hello\r\n"))
	mi := "Message-Instance: m=1; h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n"
	mf := base64.StdEncoding.EncodeToString([]byte(env.MailFrom))
	rt := base64.StdEncoding.EncodeToString([]byte(env.RcptTo[0]))
	stamp := strconv.FormatInt(testTime.Unix(), 10)
	base := "i=1;m=1;t=" + stamp + ";mf=" + mf + ";rt=" + rt + ";d=example.com;s=ed:ed25519-sha256:,rsa:rsa-sha256:;"
	input := "message-instance:m=1;h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n" + "dkim2-signature:" + base + "\r\n"
	digest := sha256.Sum256([]byte(input))
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := "DKIM2-Signature: i=1; m=1; t=" + stamp + "; mf=" + mf + "; rt=" + rt + "; d=example.com; s=ed:ed25519-sha256:" +
		base64.StdEncoding.EncodeToString(ed25519.Sign(ed, digest[:])) + ",rsa:rsa-sha256:" + base64.StdEncoding.EncodeToString(rsaSignature) + ";\r\n"
	wire := append([]byte(sig+mi), original()...)
	resolver := records{"ed._domainkey.example.com": {keyRecord(ed)}, "rsa._domainkey.example.com": {keyRecord(rsaKey)}}
	opts := VerifyOptions{Resolver: resolver, Now: testTime}
	if r := Verify(wire, env, opts); r.Status != Pass {
		t.Fatalf("two signatures=%s: %v", r.Status, r.Err)
	}
	bad := bytes.Replace(wire, []byte(base64.StdEncoding.EncodeToString(rsaSignature)), []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, len(rsaSignature)))), 1)
	if r := Verify(bad, env, opts); r.Status != Fail {
		t.Fatalf("one signature invalid=%s: %v", r.Status, r.Err)
	}
}
