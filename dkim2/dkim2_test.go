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
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
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

type policyDNSFailure struct{ key string }

func (r policyDNSFailure) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name == "s1._domainkey.mail.example.com" {
		return []string{r.key}, nil
	}
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
	case *mldsa44.PublicKey:
		return "v=DKIM1; k=mldsa44; p=" + base64.StdEncoding.EncodeToString(pub.Bytes())
	default:
		panic("unexpected key")
	}
}

func TestDraft09MLDSA44(t *testing.T) {
	var seed [mldsa44.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	public, private := mldsa44.NewKeyFromSeed(&seed)
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "pq", Key: private, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	resolver := records{"pq._domainkey.example.com": {keyRecord(private)}}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
		t.Fatalf("ML-DSA-44 status=%s: %v", got.Status, got.Err)
	}
	if len(public.Bytes()) != mldsa44.PublicKeySize {
		t.Fatal("unexpected ML-DSA-44 public key size")
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	input, err := signatureInput(parsed.Instances, nil, parsed.Signatures[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := b64(parsed.Signatures[0].Values[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if !mldsa44.Verify(public, input, []byte("DKIM2"), signature) || mldsa44.Verify(public, input, nil, signature) {
		t.Fatal("ML-DSA-44 context binding failed")
	}
	prehash := sha256.Sum256(input)
	if mldsa44.Verify(public, prehash[:], []byte("DKIM2"), signature) {
		t.Fatal("ML-DSA-44 signature unexpectedly covered SHA-256 prehash")
	}
	changed := bytes.Replace(wire, []byte("Subject: original"), []byte("Subject: altered"), 1)
	if got := Verify(changed, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Fail {
		t.Fatalf("ML-DSA-44 altered message=%s: %v", got.Status, got.Err)
	}
	resolver["pq._domainkey.example.com"] = []string{"v=DKIM1; k=mldsa44; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32))}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != PermError {
		t.Fatalf("short ML-DSA-44 key=%s: %v", got.Status, got.Err)
	}
}

func TestDraft09AuthenticFromAndPolicy(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@mail.example.com>", []string{"<bob@relay.test>"}}
	options := SignOptions{Domain: "mail.example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime, PolicyResolver: records{}}
	wire, err := Sign(original(), options)
	if err != nil {
		t.Fatalf("default subdomain permission: %v", err)
	}
	resolver := records{"s1._domainkey.mail.example.com": {keyRecord(key)}}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
		t.Fatalf("default subdomain verification=%s: %v", got.Status, got.Err)
	}
	resolver["_domainkey.example.com"] = []string{"v=DKIM1; f=strict"}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Fail {
		t.Fatalf("strict policy verification=%s: %v", got.Status, got.Err)
	}
	options.PolicyResolver = resolver
	if _, err := Sign(original(), options); err == nil {
		t.Fatal("strict policy permitted subdomain signing")
	}
	resolver["_domainkey.example.com"] = []string{"v=other; f=strict", "v=DKIM1; f=other"}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
		t.Fatalf("ignored version or unknown flag=%s: %v", got.Status, got.Err)
	}
	resolver["_domainkey.example.com"] = []string{"v=DKIM1; f=strict", "v=DKIM1; f=other"}
	if got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != PermError {
		t.Fatalf("duplicate policy=%s: %v", got.Status, got.Err)
	}
	if got := Verify(wire, env, VerifyOptions{Resolver: policyDNSFailure{keyRecord(key)}, Now: testTime}); got.Status != TempError {
		t.Fatalf("temporary policy lookup=%s: %v", got.Status, got.Err)
	}
	badFrom := bytes.Replace(original(), []byte("alice@example.com"), []byte("alice@evil.test"), 1)
	if _, err := Sign(badFrom, SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{"<alice@example.com>", env.RcptTo}, Timestamp: testTime}); err == nil {
		t.Fatal("unrelated From signed")
	}
	if _, err := Sign([]byte("From: a@example.com, b@example.com\r\n\r\nbody\r\n"), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{"<alice@example.com>", env.RcptTo}, Timestamp: testTime}); err == nil {
		t.Fatal("multiple From addresses signed")
	}
	if _, err := Sign([]byte("From: Friends: alice@example.com;\r\n\r\nbody\r\n"), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{"<alice@example.com>", env.RcptTo}, Timestamp: testTime}); err == nil {
		t.Fatal("From group syntax signed")
	}
	if _, err := Sign([]byte("From: alice@[192.0.2.1]\r\n\r\nbody\r\n"), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{"<alice@example.com>", env.RcptTo}, Timestamp: testTime}); err == nil {
		t.Fatal("From domain literal signed")
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
			if r := Verify(wire, wrong, options); r.Status != Fail {
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
	if r := Verify(forwarded, out, options); r.Status != Pass {
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
	if r := Verify(wire, env, VerifyOptions{Resolver: testingRecords, Now: testTime}); r.Status != Pass || r.Testing {
		t.Fatalf("valid testing key=%s testing=%t: %v", r.Status, r.Testing, r.Err)
	}
	changed := bytes.Replace(wire, []byte("hello\r\n"), []byte("tampered\r\n"), 1)
	if r := Verify(changed, env, VerifyOptions{Resolver: testingRecords, Now: testTime}); r.Status != Fail || r.Testing {
		t.Fatalf("testing key mismatch=%s testing=%t: %v", r.Status, r.Testing, r.Err)
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
func TestIndependentWireSignature(t *testing.T) {
	key := edKey()
	body := []byte("hello\r\n")
	hh := sha256.Sum256([]byte("from:Alice <alice@example.com>\r\nsubject:original\r\n"))
	bh := sha256.Sum256(body)
	mi := "Message-Instance: m=1; h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n"
	mf := base64.StdEncoding.EncodeToString([]byte("<alice@example.com>"))
	rt := base64.StdEncoding.EncodeToString([]byte("<bob@relay.test>"))
	stamp := strconv.FormatInt(testTime.Unix(), 10)
	sigPrefix := "s=s1:ed25519-sha256:;i=1;m=1;t=" + stamp + ";mf=" + mf + ";rt=" + rt + ";d=example.com;"
	input := "message-instance:m=1;h=sha256:" + base64.StdEncoding.EncodeToString(hh[:]) + ":" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n" +
		"dkim2-signature:" + sigPrefix + "\r\n"
	digest := sha256.Sum256([]byte(input))
	signed := base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest[:]))
	sig := "DKIM2-Signature: s=s1:ed25519-sha256:" + signed + "; i=1; m=1; t=" + stamp + "; mf=" + mf + "; rt=" + rt + "; d=example.com;\r\n"
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

func TestNullReversePathCannotSkipCustody(t *testing.T) {
	key := edKey()
	firstEnvelope := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	secondEnvelope := Envelope{"<>", []string{"<carol@destination.test>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: firstEnvelope, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	secondOptions := SignOptions{Domain: "unrelated.test", Selector: "s2", Key: key, Envelope: secondEnvelope, Timestamp: testTime}
	if _, err := Forward(first, secondOptions); err == nil {
		t.Fatal("null reverse path bypassed custody when forwarding")
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := makeSignature(parsed.Instances, parsed.Signatures, 2, secondOptions)
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(second), first...)
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.unrelated.test": {keyRecord(key)}}
	if r := Verify(forged, secondEnvelope, VerifyOptions{Resolver: resolver, Now: testTime}); r.Status != Fail {
		t.Fatalf("null reverse path bypassed custody in verifier: %s, %v", r.Status, r.Err)
	}
}

func TestUnknownKeyTypeCannotFallBackToRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "rsa", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	for _, record := range []string{"v=DKIM1; k=unknown; p=" + public, "v=DKIM1; k=ed25519:rsa; p=" + public} {
		resolver := records{"rsa._domainkey.example.com": {record}}
		if r := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime}); r.Status != PermError {
			t.Fatalf("invalid k= accepted: %s, %v", r.Status, r.Err)
		}
	}
}

func TestRejectNonNetworkNormalMessageAndInvalidPaths(t *testing.T) {
	key := edKey()
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}, Timestamp: testTime}
	for _, wire := range [][]byte{
		[]byte("From: a@example.com\r\n\r\nline\n"),
		[]byte("Received: trace\nFrom: a@example.com\r\n\r\nbody\r\n"),
	} {
		if _, err := Sign(wire, options); err == nil {
			t.Fatalf("non-network-normal message was signed: %q", wire)
		}
	}
	headerOnly, err := Sign([]byte("From: Alice <alice@example.com>\r\n"), options)
	if err != nil {
		t.Fatalf("RFC 5322 header-only message was rejected: %v", err)
	}
	if r := Verify(headerOnly, options.Envelope, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}); r.Status != Pass {
		t.Fatalf("header-only message verification=%s: %v", r.Status, r.Err)
	}
	for _, path := range []string{"<a@@example.com>", "<a b@example.com>", "<a..b@example.com>", "<a;@example.com>"} {
		options.Envelope.MailFrom = path
		if _, err := Sign(original(), options); err == nil {
			t.Fatalf("invalid MAIL FROM was signed: %q", path)
		}
	}
	options.Envelope.MailFrom = `<"a b"@example.com>`
	if _, err := Sign(original(), options); err != nil {
		t.Fatalf("valid quoted local part rejected: %v", err)
	}
	options.Envelope.MailFrom = "<alice@example.com>"
	for _, tc := range []struct{ signed, delivered string }{
		{"<Postmaster>", "<postmaster>"},
		{"<bob@[192.0.2.1]>", "<bob@[192.0.2.1]>"},
		{"<bob@[001.002.003.004]>", "<bob@[001.002.003.004]>"},
		{"<bob@[IPv6:2001:db8::1]>", "<bob@[IPv6:2001:db8::1]>"},
		{"<@RELAY.TEST:bob@RELAY.TEST>", "<@relay.test:bob@relay.test>"},
	} {
		options.Envelope.RcptTo = []string{tc.signed}
		wire, err := Sign(original(), options)
		if err != nil {
			t.Fatalf("valid RFC 5321 RCPT TO %q rejected: %v", tc.signed, err)
		}
		actual := Envelope{MailFrom: options.Envelope.MailFrom, RcptTo: []string{tc.delivered}}
		if r := Verify(wire, actual, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}); r.Status != Pass {
			t.Fatalf("valid RFC 5321 RCPT TO %q verification=%s: %v", tc.signed, r.Status, r.Err)
		}
	}
	for _, path := range []string{"<bob@[999.0.0.1]>", "<bob@[IPv6:192.0.2.1]>"} {
		options.Envelope.RcptTo = []string{path}
		if _, err := Sign(original(), options); err == nil {
			t.Fatalf("invalid address literal was signed: %q", path)
		}
	}
}

func TestNextDomainImaginaryHop(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	actual := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}, "s3._domainkey.external.test": {keyRecord(key)}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	imaginary, err := Forward(first, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, NextDomain: "external.test", Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(imaginary)
	if err != nil || parsed.Signatures[1].NextDomain != "external.test" || parsed.Signatures[1].MailFrom != "" {
		t.Fatalf("nd= signature not encoded correctly: %v, %+v", err, parsed)
	}
	if r := Verify(imaginary, actual, VerifyOptions{Resolver: resolver, Now: testTime}); r.Status != Fail {
		t.Fatalf("latest nd= without policy=%s: %v", r.Status, r.Err)
	}
	validated := false
	validator := func(sig Signature, envelope Envelope) error {
		validated = true
		if sig.NextDomain != "external.test" || envelope.MailFrom != actual.MailFrom {
			return errors.New("unexpected arrangement")
		}
		return nil
	}
	if r := Verify(imaginary, actual, VerifyOptions{Resolver: resolver, Now: testTime, ValidateNextDomain: validator}); r.Status != Fail || !validated {
		t.Fatalf("latest nd= with policy=%s: %v", r.Status, r.Err)
	}
	if r := Verify(imaginary, actual, VerifyOptions{Resolver: resolver, Now: testTime, ValidateNextDomain: func(Signature, Envelope) error { return errors.New("denied") }}); r.Status != Fail {
		t.Fatalf("denied nd= arrangement=%s: %v", r.Status, r.Err)
	}
	out := Envelope{"<sender@external.test>", []string{"<dest@example.net>"}}
	forwarded, err := Forward(imaginary, SignOptions{Domain: "external.test", Selector: "s3", Key: key, Envelope: out, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(forwarded, out, VerifyOptions{Resolver: resolver, Now: testTime}); r.Status != Pass {
		t.Fatalf("completed nd= chain=%s: %v", r.Status, r.Err)
	}
	if _, err := Forward(imaginary, SignOptions{Domain: "wrong.test", Selector: "s3", Key: key, Envelope: Envelope{"<sender@wrong.test>", out.RcptTo}, Timestamp: testTime}); err == nil {
		t.Fatal("nd= accepted the wrong next signer")
	}
}

func TestNullBodyRecipeRequiresExplicitPartialVerification(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}
	initial, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	modified := append(append([]byte(nil), initial...), []byte("footer\r\n")...)
	options := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime}
	if _, err := Revise(modified, []byte(`{"b":null}`), options); err == nil {
		t.Fatal("null body Recipe accepted without explicit option")
	}
	options.AllowNullBodyRecipe = true
	revised, err := Revise(modified, []byte(`{"b":null}`), options)
	if err != nil {
		t.Fatal(err)
	}
	verifyOptions := VerifyOptions{Resolver: resolver, Now: testTime}
	if r := Verify(revised, out, verifyOptions); r.Status != PermError {
		t.Fatalf("null body Recipe without partial policy=%s: %v", r.Status, r.Err)
	}
	verifyOptions.AllowPartialBody = true
	if r := Verify(revised, out, verifyOptions); r.Status != PermError || len(r.UnverifiedBodies) != 1 || r.UnverifiedBodies[0] != 1 {
		t.Fatalf("partial verification=%s unverified=%v: %v", r.Status, r.UnverifiedBodies, r.Err)
	}
	tampered := bytes.Replace(revised, []byte("footer\r\n"), []byte("tampered\r\n"), 1)
	if r := Verify(tampered, out, verifyOptions); r.Status != Fail {
		t.Fatalf("latest body tampering under partial policy=%s: %v", r.Status, r.Err)
	}
}

func TestCheckedForwardingAuthenticatesIncomingMessage(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	verifyOptions := VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}
	nextOptions := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime}
	if _, err := ForwardChecked(first, in, verifyOptions, nextOptions); err != nil {
		t.Fatalf("valid incoming message was not forwarded: %v", err)
	}
	tampered := bytes.Replace(first, []byte("hello\r\n"), []byte("changed\r\n"), 1)
	if _, err := ForwardChecked(tampered, in, verifyOptions, nextOptions); err == nil {
		t.Fatal("tampered incoming message was forwarded")
	}
	modified := append(append([]byte(nil), first...), []byte("footer\r\n")...)
	if _, err := ReviseChecked(first, modified, in, verifyOptions, []byte(`{"b":[{"c":[1,1]}]}`), nextOptions); err != nil {
		t.Fatalf("valid incoming message was not revised: %v", err)
	}
	changedPrior := bytes.Replace(modified, []byte("Message-Instance: m=1;"), []byte("Message-Instance: m=01;"), 1)
	if _, err := ReviseChecked(first, changedPrior, in, verifyOptions, []byte(`{"b":[{"c":[1,1]}]}`), nextOptions); err == nil {
		t.Fatal("changed prior DKIM2 field was signed")
	}
}

func TestReplayHookAfterAuthentication(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	calls := 0
	options := VerifyOptions{Resolver: resolver, Now: testTime, ReplayCheck: func(id string) (bool, error) {
		calls++
		if id == "" {
			t.Fatal("empty replay ID")
		}
		duplicate := seen[id]
		seen[id] = true
		return duplicate, nil
	}}
	first := Verify(wire, env, options)
	if first.Status != Pass || first.ReplayID == "" || first.ReplayDetected || first.ReplayErr != nil {
		t.Fatalf("first delivery=%s id=%q: %v", first.Status, first.ReplayID, first.Err)
	}
	second := Verify(wire, env, options)
	if second.Status != Pass || !second.ReplayDetected || second.ReplayID != first.ReplayID || calls != 2 {
		t.Fatalf("duplicate delivery=%s id=%q calls=%d: %v", second.Status, second.ReplayID, calls, second.Err)
	}
	tampered := bytes.Replace(wire, []byte("hello\r\n"), []byte("wrong\r\n"), 1)
	if r := Verify(tampered, env, options); r.Status != Fail || calls != 2 {
		t.Fatalf("invalid message entered replay store: %s, calls=%d", r.Status, calls)
	}
	if _, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime, Flags: []string{"exploded"}}); err == nil {
		t.Fatal("initial exploded flag accepted")
	}
	options.ReplayCheck = func(string) (bool, error) { return false, errors.New("storage unavailable") }
	if r := Verify(wire, env, options); r.Status != Pass || r.ReplayErr == nil {
		t.Fatalf("unavailable replay store=%s replay error=%v", r.Status, r.ReplayErr)
	}
}
