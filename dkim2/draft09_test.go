package dkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDraft09HashAlgebra(t *testing.T) {
	m, err := Parse(original())
	if err != nil {
		t.Fatal(err)
	}
	h256, _ := headerDigest(m.Headers, "sha256")
	b256, _ := bodyDigest(m.Body, "sha256")
	h512, _ := headerDigest(m.Headers, "sha512")
	b512, _ := bodyDigest(m.Body, "sha512")
	bad := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		value string
		want  Status
	}{
		{"sha256:" + bad + ":" + b256 + "|sha512:" + h512 + ":" + b512, Pass},
		{"sha256:" + bad + ":" + b256 + ",sha512:" + h512 + ":" + b512, Fail},
		{"future:" + h256 + ":" + b256 + "|sha512:" + h512 + ":" + b512, Pass},
		{"future:" + h256 + ":" + b256 + ",sha512:" + h512 + ":" + b512, PermError},
	} {
		inst, err := parseInstance("Message-Instance: m=1; h=" + tc.value + ";\r\n")
		if err != nil {
			t.Fatal(err)
		}
		err = checkInstanceHash(m, inst)
		status := Pass
		if err != nil {
			var statusErr *statusError
			if !errors.As(err, &statusErr) {
				t.Fatal(err)
			}
			status = statusErr.status
		}
		if status != tc.want {
			t.Fatalf("h=%s gave %s, want %s: %v", tc.value, status, tc.want, err)
		}
	}
	inst, err := parseInstance("Message-Instance: m=1; h=sha256:" + bad + ":" + b256 + "|sha512:" + h512 + ":" + b512 + ";\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if id := firstInstanceReplayID(m, inst); id != "sha512:"+h512+":"+b512 {
		t.Fatalf("ReplayID used a failing hash alternative: %q", id)
	}
	if _, err := parseInstance("Message-Instance: m=1; h=sha256:" + h256 + ":" + b256 + "|sha256:" + h256 + ":" + b256 + ";\r\n"); err == nil {
		t.Fatal("duplicate algorithm across groups accepted")
	}
}

func TestDraft09SignatureAlgebra(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	m, err := Parse(original())
	if err != nil {
		t.Fatal(err)
	}
	hh, _ := headerDigest(m.Headers, "sha256")
	bh, _ := bodyDigest(m.Body, "sha256")
	mi := fmt.Sprintf("Message-Instance: m=1; h=sha256:%s:%s;\r\n", hh, bh)
	inst := Instance{Number: 1, Raw: mi}
	for _, tc := range []struct {
		separator string
		want      Status
	}{{"|", Pass}, {",", Fail}} {
		first := "bad:ed25519-sha256:"
		second := "good:ed25519-sha256:"
		template := fmt.Sprintf("DKIM2-Signature: i=1; m=1; t=%d; mf=%s; rt=%s; d=example.com; s=%s%s%s;\r\n", testTime.Unix(), base64.StdEncoding.EncodeToString([]byte(env.MailFrom)), base64.StdEncoding.EncodeToString([]byte(env.RcptTo[0])), first, tc.separator, second)
		input, err := signatureInput([]Instance{inst}, nil, template)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(input)
		bad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize))
		good := base64.StdEncoding.EncodeToString(ed25519.Sign(key, hash[:]))
		sig := strings.Replace(template, first, first+bad, 1)
		sig = strings.Replace(sig, second, second+good, 1)
		wire := append([]byte(sig+mi), original()...)
		resolver := records{"bad._domainkey.example.com": {keyRecord(key)}, "good._domainkey.example.com": {keyRecord(key)}}
		got := Verify(wire, env, VerifyOptions{Resolver: resolver, Now: testTime})
		if got.Status != tc.want {
			t.Fatalf("s= separator %q gave %s, want %s: %v", tc.separator, got.Status, tc.want, got.Err)
		}
	}
}

func TestDraft09UnchangedInstanceNeedsNoRecipe(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<sender@relay.test>", []string{"<carol@example.net>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	h := parsed.Instances[0].Hashes[0]
	raw := fmt.Sprintf("Message-Instance: m=2; h=%s:%s:%s;\r\n", h.Algorithm, h.Header, h.Body)
	instances := append(parsed.Instances, Instance{Number: 2, Raw: raw, Hashes: []HashSet{h}})
	sig, err := makeSignature(instances, parsed.Signatures, 2, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(sig+raw), first...)
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}
	if got := Verify(wire, out, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
		t.Fatalf("unchanged m=2 without Recipe=%s: %v", got.Status, got.Err)
	}
}

func TestDraft09AuthenticFromAfterRevision(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Replace(first, []byte("alice@example.com"), []byte("alice@relay.test"), 1)
	recipe := []byte(`{"h":{"from":[{"d":[" Alice <alice@example.com>"]}]}}`)
	wire, err := revise(modified, recipe, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}
	if got := Verify(wire, out, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
		t.Fatalf("authentic revised From=%s: %v", got.Status, got.Err)
	}
	forged := bytes.Replace(first, []byte("alice@example.com"), []byte("alice@evil.test"), 1)
	if _, err := revise(forged, recipe, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime}); err == nil {
		t.Fatal("unrelated revised From was signed")
	}
}

func TestDraft09EAIMapsDomainWithoutChangingLocalPart(t *testing.T) {
	key := edKey()
	domain := "xn--r8jz45g.xn--zckzah"
	message := []byte("From: 山田 <ユーザー@例え.テスト>\r\nSubject: EAI\r\n\r\nhello\r\n")
	env := Envelope{"<ユーザー@例え.テスト>", []string{"<受信者@例え.テスト>"}}
	wire, err := Sign(message, SignOptions{Domain: domain, Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].MailFrom != "<ユーザー@"+domain+">" || parsed.Signatures[0].Recipients[0] != "<受信者@"+domain+">" {
		t.Fatalf("U-label was not mapped to A-label: %+v", parsed.Signatures[0])
	}
	resolver := records{"s1._domainkey." + domain: {keyRecord(key)}}
	for _, actual := range []Envelope{env, {"<ユーザー@" + domain + ">", []string{"<受信者@" + domain + ">"}}} {
		if got := Verify(wire, actual, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Pass {
			t.Fatalf("EAI verification=%s: %v", got.Status, got.Err)
		}
	}
	wrong := Envelope{"<別@例え.テスト>", env.RcptTo}
	if got := Verify(wire, wrong, VerifyOptions{Resolver: resolver, Now: testTime}); got.Status != Fail {
		t.Fatalf("changed EAI local part=%s: %v", got.Status, got.Err)
	}
}
