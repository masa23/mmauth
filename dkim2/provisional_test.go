package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func provisionalFixture(t *testing.T) ([]byte, Envelope, records) {
	t.Helper()
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Forward(first, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime, OutOfBandArrangement: true})
	if err != nil {
		t.Fatal(err)
	}
	return wire, out, records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}
}

func TestProvisionalOnlyFetchesLatestKey(t *testing.T) {
	wire, envelope, resolver := provisionalFixture(t)
	delete(resolver, "s1._domainkey.example.com")
	calls := 0
	options := VerifyOptions{Resolver: resolver, Now: testTime, ReplayCheck: func(string) (bool, error) {
		calls++
		return false, nil
	}}
	result := VerifyProvisional(wire, envelope, options)
	if result.Status != Pass || result.Err != nil || result.PendingNextDomain || calls != 0 {
		t.Fatalf("provisional=%+v replay calls=%d", result, calls)
	}
	if got := Verify(wire, envelope, options); got.Status != PermError {
		t.Fatalf("full verification incorrectly skipped old key: %+v", got)
	}
}

func TestProvisionalAuthenticatesCurrentMessageAndEnvelope(t *testing.T) {
	wire, envelope, resolver := provisionalFixture(t)
	for _, test := range []struct {
		name     string
		wire     []byte
		envelope Envelope
	}{
		{"body", bytes.Replace(wire, []byte("hello\r\n"), []byte("changed\r\n"), 1), envelope},
		{"header", bytes.Replace(wire, []byte("Subject: original"), []byte("Subject: changed"), 1), envelope},
		{"mail from", wire, Envelope{"<forged@relay.test>", envelope.RcptTo}},
		{"recipient", wire, Envelope{envelope.MailFrom, []string{"<other@destination.test>"}}},
		{"missing recipients", wire, Envelope{MailFrom: envelope.MailFrom}},
		{"missing envelope", wire, Envelope{}},
		{"injected envelope", wire, Envelope{envelope.MailFrom, []string{"<x@destination.test>\r\nInjected: yes"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := VerifyProvisional(test.wire, test.envelope, VerifyOptions{Resolver: resolver, Now: testTime})
			if got.Status != Fail || got.Err == nil || got.PendingNextDomain {
				t.Fatalf("provisional=%+v", got)
			}
		})
	}
}

// Re-sign the latest hop after deliberately damaging historical information.
// Its signature covers the damage, but provisional verification must not treat
// the historical fields as independently authenticated.
func TestProvisionalDoesNotClaimHistoricalVerification(t *testing.T) {
	key := edKey()
	firstEnvelope := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: firstEnvelope, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*Message)
	}{
		{"old signature", func(m *Message) { m.Signatures[0].Raw = strings.Replace(m.Signatures[0].Raw, "s=s1:", "s=missing:", 1) }},
		{"old timestamp", func(m *Message) {
			m.Signatures[0].Raw = strings.Replace(m.Signatures[0].Raw, fmt.Sprintf("t=%d", testTime.Unix()), "t=0", 1)
		}},
		{"old recipe", func(m *Message) {
			m.Instances[0].Raw = strings.TrimSuffix(m.Instances[0].Raw, "\r\n") + "r=" + base64.StdEncoding.EncodeToString([]byte("invalid JSON")) + ";\r\n"
		}},
		{"custody", func(m *Message) {
			m.Signatures[0].Raw = strings.Replace(m.Signatures[0].Raw, base64.StdEncoding.EncodeToString([]byte("<bob@relay.test>")), base64.StdEncoding.EncodeToString([]byte("<bob@other.test>")), 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := Parse(first)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(m)
			out := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
			sig, err := makeSignature(m.Instances, m.Signatures, 2, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime})
			if err != nil {
				t.Fatal(err)
			}
			wire := []byte(sig + m.Signatures[0].Raw + m.Instances[0].Raw + string(original()))
			options := VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}, Now: testTime}
			if got := VerifyProvisional(wire, out, options); got.Status != Pass {
				t.Fatalf("latest signature should pass: %+v", got)
			}
			if got := Verify(wire, out, options); got.Status == Pass {
				t.Fatalf("damaged history fully verified: %+v", got)
			}
		})
	}
}

func provisionalSingle(t *testing.T, message []byte, instanceNumber, signatureNumber int, options SignOptions) []byte {
	t.Helper()
	m, err := Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	hh, _ := headerDigest(m.Headers, "sha256")
	bh, _ := bodyDigest(m.Body, "sha256")
	mi := fmt.Sprintf("Message-Instance: m=%d; h=sha256:%s:%s;\r\n", instanceNumber, hh, bh)
	sig, err := makeSignature([]Instance{{Number: instanceNumber, Raw: mi}}, nil, signatureNumber, options)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(sig+mi), message...)
}

func TestProvisionalChecksOnlyLatestConsistency(t *testing.T) {
	key := edKey()
	envelope := Envelope{"<alice@example.com>", []string{"<bob@destination.test>"}}
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: envelope, Timestamp: testTime}
	verification := VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}
	wire := provisionalSingle(t, original(), 9, 12, options)
	if got := VerifyProvisional(wire, envelope, verification); got.Status != Pass {
		t.Fatalf("historical gaps prevented latest-hop assessment: %+v", got)
	}
	if got := Verify(wire, envelope, verification); got.Status != PermError {
		t.Fatalf("historical gaps fully verified: %+v", got)
	}
	bad := bytes.Replace(wire, []byte("m=9;"), []byte("m=8;"), 1)
	if got := VerifyProvisional(bad, envelope, verification); got.Status != Fail {
		t.Fatalf("latest m= mismatch accepted: %+v", got)
	}
	parsed, _ := Parse(wire)
	for _, duplicate := range []string{parsed.Instances[0].Raw, parsed.Signatures[0].Raw} {
		if got := VerifyProvisional(append([]byte(duplicate), wire...), envelope, verification); got.Status != PermError {
			t.Fatalf("ambiguous duplicate accepted: %+v", got)
		}
	}
	foreignFrom := []byte("From: alice@unrelated.test\r\n\r\nbody\r\n")
	wire = provisionalSingle(t, foreignFrom, 1, 1, options)
	if got := VerifyProvisional(wire, envelope, verification); got.Status != Pass {
		t.Fatalf("provisional must not claim Authentic From checking: %+v", got)
	}
	if got := Verify(wire, envelope, verification); got.Status != Fail {
		t.Fatalf("foreign From fully verified: %+v", got)
	}
	options.Envelope.MailFrom = "<bounce@unrelated.test>"
	wire = provisionalSingle(t, original(), 1, 1, options)
	if got := VerifyProvisional(wire, options.Envelope, verification); got.Status != Fail {
		t.Fatalf("latest mf=/d= mismatch accepted: %+v", got)
	}
}

func TestProvisionalNextDomainRequiresExplicitArrangement(t *testing.T) {
	wire, envelope, resolver := provisionalFixture(t)
	parsed, _ := Parse(wire)
	latest, err := makeSignature(parsed.Instances, parsed.Signatures, 3, SignOptions{Domain: "destination.test", Selector: "s3", Key: edKey(), NextDomain: "next.test", Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	wire = append([]byte(latest), wire...)
	resolver["s3._domainkey.destination.test"] = []string{keyRecord(edKey())}
	options := VerifyOptions{Resolver: resolver, Now: testTime}
	if got := VerifyProvisional(wire, envelope, options); got.Status != Fail || got.PendingNextDomain {
		t.Fatalf("nd= without arrangement accepted: %+v", got)
	}
	called := 0
	options.ValidateNextDomain = func(sig Signature, got Envelope) error {
		called++
		if sig.NextDomain != "next.test" || got.MailFrom != envelope.MailFrom {
			return errors.New("incorrect arrangement")
		}
		return nil
	}
	if got := VerifyProvisional(wire, envelope, options); got.Status != Pass || !got.PendingNextDomain || called != 1 {
		t.Fatalf("explicit nd= arrangement rejected: %+v called=%d", got, called)
	}
	options.ValidateNextDomain = func(Signature, Envelope) error { return errors.New("not permitted") }
	if got := VerifyProvisional(wire, envelope, options); got.Status != Fail || got.PendingNextDomain {
		t.Fatalf("denied nd= arrangement accepted: %+v", got)
	}
}

type provisionalCountingResolver struct {
	base  records
	calls int
}

func (r *provisionalCountingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.calls++
	return r.base.LookupTXT(ctx, name)
}

func TestProvisionalDNSStatusAndBudgets(t *testing.T) {
	wire, envelope, resolver := provisionalFixture(t)
	for _, test := range []struct {
		name    string
		options VerifyOptions
		want    Status
	}{
		{"missing key", VerifyOptions{Resolver: records{}, Now: testTime}, PermError},
		{"temporary DNS", VerifyOptions{Resolver: dnsFailure{}, Now: testTime}, TempError},
		{"negative lookups", VerifyOptions{Resolver: resolver, Now: testTime, MaxDNSLookups: -1}, PermError},
		{"negative time", VerifyOptions{Resolver: resolver, Now: testTime, DNSBudget: -1}, PermError},
		{"deadline", VerifyOptions{Resolver: waitForContextResolver{}, Now: testTime, DNSBudget: time.Millisecond}, TempError},
		{"old newest timestamp", VerifyOptions{Resolver: resolver, Now: testTime.Add(15 * 24 * time.Hour)}, Fail},
		{"future newest timestamp", VerifyOptions{Resolver: resolver, Now: testTime.Add(-2 * 24 * time.Hour)}, Fail},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := VerifyProvisional(wire, envelope, test.options); got.Status != test.want {
				t.Fatalf("provisional=%+v want=%s", got, test.want)
			}
		})
	}
	counting := &provisionalCountingResolver{base: resolver}
	if got := VerifyProvisional(wire, envelope, VerifyOptions{Resolver: counting, Now: testTime, MaxDNSLookups: 1}); got.Status != Pass || counting.calls != 1 {
		t.Fatalf("latest-hop DNS count: %+v calls=%d", got, counting.calls)
	}
	// The first failed alternative consumes the sole DNS lookup; the second
	// cannot exceed the shared budget even though it is a passing signature.
	hybrid, envelope := signatureAlgebraWire(t, "ed25519-sha256", make([]byte, 64), "|", false)
	counting = &provisionalCountingResolver{base: records{"good._domainkey.example.com": {keyRecord(edKey())}}}
	if got := VerifyProvisional(hybrid, envelope, VerifyOptions{Resolver: counting, Now: testTime, MaxDNSLookups: 1}); got.Status != PermError || counting.calls != 1 {
		t.Fatalf("DNS budget bypassed: %+v calls=%d", got, counting.calls)
	}
	if got := VerifyProvisional(hybrid, envelope, VerifyOptions{Resolver: counting, Now: testTime, MaxDNSLookups: 2}); got.Status != Pass {
		t.Fatalf("OR alternative not evaluated: %+v", got)
	}
}

func TestProvisionalUnsignedAndMalformedInput(t *testing.T) {
	if got := VerifyProvisional(original(), Envelope{}, VerifyOptions{}); got.Status != None || got.PendingNextDomain || got.Err != nil {
		t.Fatalf("unsigned result=%+v", got)
	}
	for _, input := range [][]byte{nil, []byte("From: a@example.com\n\nbody\n"), []byte("Message-Instance: broken\r\n\r\nbody\r\n")} {
		if got := VerifyProvisional(input, Envelope{}, VerifyOptions{}); got.Status != PermError || got.Err == nil {
			t.Fatalf("malformed result=%+v", got)
		}
	}
}
