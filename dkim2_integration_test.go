package mmauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/masa23/mmauth/dkim2"
)

type dkim2TestResolver struct {
	records map[string][]string
	lookups int
}

func (r *dkim2TestResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.lookups++
	if records, ok := r.records[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

func dkim2TestMessage(t *testing.T) ([]byte, dkim2.Envelope, *dkim2TestResolver, time.Time) {
	t.Helper()
	when := time.Unix(1780000000, 0)
	envelope := dkim2.Envelope{MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.test>"}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	wire, err := dkim2.Sign([]byte("From: Alice <alice@example.com>\r\nTo: Bob <bob@relay.test>\r\nSubject: hello\r\n\r\nbody\r\n"), dkim2.SignOptions{
		Domain: "example.com", Selector: "s1", Key: key, Envelope: envelope, Timestamp: when,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &dkim2TestResolver{records: map[string][]string{
		"s1._domainkey.example.com": {"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))},
	}}
	return wire, envelope, resolver, when
}

func writeAndVerify(t *testing.T, m *MMAuth, wire []byte) {
	t.Helper()
	for len(wire) > 0 {
		n := 7
		if len(wire) < n {
			n = len(wire)
		}
		if written, err := m.Write(wire[:n]); err != nil || written != n {
			t.Fatalf("Write() = %d, %v", written, err)
		}
		wire = wire[n:]
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	m.Verify()
}

func countDKIM2AuthResults(results []string) int {
	count := 0
	for _, result := range results {
		if strings.HasPrefix(result, "dkim2=") {
			count++
		}
	}
	return count
}

func TestDKIM2DefaultAndDisabledKeepLegacyResults(t *testing.T) {
	wire, envelope, resolver, when := dkim2TestMessage(t)
	legacy := NewMMAuth()
	writeAndVerify(t, legacy, wire)
	if got := legacy.GetDKIM2Verification(); got.Enabled || got.Checked || got.Err != nil {
		t.Fatalf("default DKIM2 state = %+v", got)
	}

	disabled, err := NewMMAuthWithOptions(MMAuthOptions{
		EnableDKIM2: false, DKIM2Envelope: envelope,
		DKIM2VerifyOptions:   dkim2.VerifyOptions{Resolver: resolver, Now: when},
		DKIM2MaxMessageBytes: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, disabled, wire)
	if resolver.lookups != 0 {
		t.Fatalf("disabled DKIM2 performed %d DNS lookups", resolver.lookups)
	}
	if got := disabled.GetDKIM2Verification(); got.Enabled || got.Checked || got.Err != nil {
		t.Fatalf("disabled DKIM2 state = %+v", got)
	}
	if !reflect.DeepEqual(legacy.Headers, disabled.Headers) || !reflect.DeepEqual(legacy.bodyHashed, disabled.bodyHashed) {
		t.Fatal("disabled DKIM2 changed legacy parsing or body hashes")
	}
	legacyResults := legacy.GetAuthenticationHeader(nil, "", "")
	disabledResults := disabled.GetAuthenticationHeader(nil, "", "")
	if !reflect.DeepEqual(legacyResults, disabledResults) || countDKIM2AuthResults(disabledResults) != 0 {
		t.Fatalf("legacy results changed: %v vs %v", legacyResults, disabledResults)
	}
	malformed := []byte("From: Alice <alice@example.com>\r\nDKIM2-Signature: invalid\r\nMessage-Instance: invalid\r\n\r\nbody\r\n")
	ignored := NewMMAuth()
	writeAndVerify(t, ignored, malformed)
	if got := ignored.GetDKIM2Verification(); got.Enabled || got.Checked || got.Err != nil {
		t.Fatalf("malformed DKIM2 was processed without opt-in: %+v", got)
	}
}

func TestDKIM2OptInPassAndReplayOnlyOnce(t *testing.T) {
	wire, envelope, resolver, when := dkim2TestMessage(t)
	replayCalls := 0
	m, err := NewMMAuthWithOptions(MMAuthOptions{
		EnableDKIM2: true, DKIM2Envelope: envelope,
		DKIM2VerifyOptions: dkim2.VerifyOptions{Resolver: resolver, Now: when, ReplayCheck: func(id string) (bool, error) {
			replayCalls++
			if id == "" {
				t.Fatal("empty ReplayID")
			}
			return true, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, m, wire)
	m.Verify()
	got := m.GetDKIM2Verification()
	if !got.Enabled || !got.Checked || got.Result.Status != dkim2.Pass || !got.Result.ReplayDetected || got.Err != nil {
		t.Fatalf("DKIM2 state = %+v", got)
	}
	if replayCalls != 1 || resolver.lookups == 0 {
		t.Fatalf("replay calls=%d, DNS lookups=%d", replayCalls, resolver.lookups)
	}
	if m.dkim2.raw.Len() != 0 {
		t.Fatal("raw message retained after verification")
	}
	results := m.GetAuthenticationHeader(nil, "", "")
	if countDKIM2AuthResults(results) != 1 || results[len(results)-1] != "dkim2=pass" {
		t.Fatalf("Authentication-Results = %v", results)
	}
}

func TestDKIM2OptInNoneSkipsBodyCapture(t *testing.T) {
	envelope := dkim2.Envelope{MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.test>"}}
	m, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: envelope, DKIM2MaxMessageBytes: 80})
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte("From: Alice <alice@example.com>\r\n\r\n"), bytes.Repeat([]byte("body\r\n"), 100)...)
	writeAndVerify(t, m, wire)
	got := m.GetDKIM2Verification()
	if !got.Checked || got.Result.Status != dkim2.None || got.Err != nil || m.dkim2.raw.Len() != 0 {
		t.Fatalf("unsigned DKIM2 state = %+v", got)
	}
}

func TestDKIM2LimitAndFailuresDoNotStopLegacyProcessing(t *testing.T) {
	wire, envelope, resolver, when := dkim2TestMessage(t)
	limited, err := NewMMAuthWithOptions(MMAuthOptions{
		EnableDKIM2: true, DKIM2Envelope: envelope, DKIM2MaxMessageBytes: 20,
		DKIM2VerifyOptions: dkim2.VerifyOptions{Resolver: resolver, Now: when},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, limited, wire)
	got := limited.GetDKIM2Verification()
	if !got.Enabled || got.Checked || !errors.Is(got.Err, ErrDKIM2MessageTooLarge) {
		t.Fatalf("limited DKIM2 state = %+v", got)
	}
	if limited.AuthenticationHeaders == nil || countDKIM2AuthResults(limited.GetAuthenticationHeader(nil, "", "")) != 0 {
		t.Fatal("capture limit affected legacy authentication results")
	}
	if resolver.lookups != 0 {
		t.Fatal("oversize message attempted DKIM2 DNS lookup")
	}

	bad := bytes.Replace(wire, []byte("DKIM2-Signature: i=1;"), []byte("DKIM2-Signature: i=bad;"), 1)
	if bytes.Equal(bad, wire) {
		t.Fatal("failed to corrupt test signature")
	}
	m, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, m, bad)
	got = m.GetDKIM2Verification()
	if !got.Checked || got.Result.Status != dkim2.PermError || got.Err != nil {
		t.Fatalf("malformed DKIM2 state = %+v", got)
	}
	if m.AuthenticationHeaders == nil || countDKIM2AuthResults(m.GetAuthenticationHeader(nil, "", "")) != 1 {
		t.Fatal("malformed DKIM2 affected legacy authentication results")
	}
}

func TestDKIM2OptInRequiresEnvelopeAndValidLimit(t *testing.T) {
	for _, options := range []MMAuthOptions{
		{EnableDKIM2: true},
		{EnableDKIM2: true, DKIM2Envelope: dkim2.Envelope{MailFrom: "<alice@example.com>"}},
		{EnableDKIM2: true, DKIM2Envelope: dkim2.Envelope{MailFrom: "<alice@example.com>", RcptTo: []string{""}}},
		{EnableDKIM2: true, DKIM2Envelope: dkim2.Envelope{MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@example.com>"}}, DKIM2MaxMessageBytes: -1},
	} {
		if m, err := NewMMAuthWithOptions(options); err == nil {
			m.Close()
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
}

func TestDKIM2OptInEnvelopeMismatchIsSeparateFailure(t *testing.T) {
	wire, envelope, resolver, when := dkim2TestMessage(t)
	envelope.RcptTo = []string{"<other@relay.test>"}
	m, err := NewMMAuthWithOptions(MMAuthOptions{
		EnableDKIM2: true, DKIM2Envelope: envelope,
		DKIM2VerifyOptions: dkim2.VerifyOptions{Resolver: resolver, Now: when},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, m, wire)
	got := m.GetDKIM2Verification()
	if !got.Checked || got.Result.Status != dkim2.Fail || got.Err != nil {
		t.Fatalf("mismatched envelope state = %+v", got)
	}
	results := m.GetAuthenticationHeader(nil, "", "")
	if countDKIM2AuthResults(results) != 1 || results[len(results)-1] != "dkim2=fail" {
		t.Fatalf("Authentication-Results = %v", results)
	}
}
