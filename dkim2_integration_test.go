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
	if countDKIM2AuthResults(results) != 1 || !strings.HasPrefix(results[len(results)-1], "dkim2=fail (") {
		t.Fatalf("Authentication-Results = %v", results)
	}
}

func TestDKIM2StillVerifiesWhenUnsignedDKIMHeaderIsMalformed(t *testing.T) {
	wire, envelope, resolver, when := dkim2TestMessage(t)
	wire = append([]byte("DKIM-Signature: invalid\r\n"), wire...)
	options := dkim2.VerifyOptions{Resolver: resolver, Now: when}
	if direct := dkim2.Verify(wire, envelope, options); direct.Status != dkim2.Pass {
		t.Fatalf("direct DKIM2 verification=%s: %v", direct.Status, direct.Err)
	}
	legacy := NewMMAuth()
	if _, err := legacy.Write(wire); err != nil {
		t.Fatal(err)
	}
	legacyCloseErr := legacy.Close()
	legacy.Verify()
	legacyResults := legacy.GetAuthenticationHeader(nil, "", "")
	if got := legacy.GetDKIM2Verification(); got.Enabled || got.Checked || got.Err != nil {
		t.Fatalf("legacy DKIM2 state=%+v", got)
	}
	m, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: envelope, DKIM2VerifyOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Write(wire); err != nil {
		t.Fatal(err)
	}
	closeErr := m.Close()
	if (closeErr == nil) != (legacyCloseErr == nil) || closeErr != nil && closeErr.Error() != legacyCloseErr.Error() {
		t.Fatalf("malformed DKIM Close error changed: enabled=%v legacy=%v", closeErr, legacyCloseErr)
	}
	m.Verify()
	state := m.GetDKIM2Verification()
	if !state.Checked || state.Result.Status != dkim2.Pass || state.Err != nil {
		t.Fatalf("DKIM2 state=%+v", state)
	}
	results := m.GetAuthenticationHeader(nil, "", "")
	if len(results) != len(legacyResults)+1 || !reflect.DeepEqual(results[:len(legacyResults)], legacyResults) || results[len(results)-1] != "dkim2=pass" {
		t.Fatalf("Authentication-Results=%v", results)
	}
}

// TestDKIM2StillVerifiesWhenDKIMLimitExceeded keeps main's legacy limit and
// avoids body-hash work while retaining the opt-in DKIM2 message independently.
func TestDKIM2StillVerifiesWhenDKIMLimitExceeded(t *testing.T) {
	_, envelope, resolver, when := dkim2TestMessage(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	original := []byte("From: Alice <alice@example.com>\r\n\r\n" + strings.Repeat("body\r\n", 4096))
	wire, err := dkim2.Sign(original, dkim2.SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: envelope, Timestamp: when})
	if err != nil {
		t.Fatal(err)
	}
	wire = append([]byte(strings.Repeat("DKIM-Signature: invalid\r\n", maxDKIMSignaturesPerMessage+1)), wire...)
	verification := dkim2.VerifyOptions{Resolver: resolver, Now: when}
	if direct := dkim2.Verify(wire, envelope, verification); direct.Status != dkim2.Pass {
		t.Fatalf("direct DKIM2 verification: %+v", direct)
	}
	legacy := NewMMAuth()
	_, _ = legacy.Write(wire)
	legacyErr := legacy.Close()
	if legacyErr == nil || !strings.Contains(legacyErr.Error(), "too many DKIM signatures") {
		t.Fatalf("legacy signature limit changed: %v", legacyErr)
	}
	legacy.Verify()
	legacyResults := legacy.GetAuthenticationHeader(nil, "", "")
	m, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: envelope, DKIM2VerifyOptions: verification})
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := m.Write(wire)
	closeErr := m.Close()
	if writeErr != nil || closeErr == nil || closeErr.Error() != legacyErr.Error() {
		t.Fatalf("DKIM2 capture or legacy signature limit failed: write=%v close=%v", writeErr, closeErr)
	}
	if len(m.bodyHashList) != 0 || len(m.bodyHashed) != 0 {
		t.Fatal("legacy body hashes registered despite the signature limit")
	}
	m.Verify()
	state := m.GetDKIM2Verification()
	if !state.Checked || state.Result.Status != dkim2.Pass || state.Err != nil {
		t.Fatalf("legacy signature count suppressed DKIM2: %+v", state)
	}
	results := m.GetAuthenticationHeader(nil, "", "")
	if len(results) != len(legacyResults)+1 || !reflect.DeepEqual(results[:len(legacyResults)], legacyResults) || results[len(results)-1] != "dkim2=pass" {
		t.Fatalf("legacy results changed: %v", results)
	}
	limited, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: envelope, DKIM2VerifyOptions: verification, DKIM2MaxMessageBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = limited.Write(wire)
	if err := limited.Close(); err == nil || err.Error() != legacyErr.Error() {
		t.Fatalf("capture overflow replaced legacy signature-limit error: %v", err)
	}
	resolver.lookups = 0
	limited.Verify()
	state = limited.GetDKIM2Verification()
	if state.Checked || !errors.Is(state.Err, ErrDKIM2MessageTooLarge) || limited.dkim2.raw.Len() != 0 || resolver.lookups != 0 {
		t.Fatalf("signature-limit remainder bypassed capture budget: %+v lookups=%d", state, resolver.lookups)
	}
	if len(limited.bodyHashList) != 0 || len(limited.bodyHashed) != 0 {
		t.Fatal("capture overflow registered legacy body hashes")
	}
}

func TestDKIM2AuthenticationCommentEscapesUntrustedText(t *testing.T) {
	result := dkim2.Result{Status: dkim2.Fail, Err: errors.New("bad)\r\nInjected: pass (\\" + strings.Repeat("x", 300))}
	got := dkim2AuthenticationResult(result)
	if !strings.HasPrefix(got, "dkim2=fail (") || strings.ContainsAny(got, "\r\n") ||
		!strings.Contains(got, "\\)") || !strings.Contains(got, "\\(") || !strings.Contains(got, "\\\\") || len(got) > 210 {
		t.Fatalf("unsafe DKIM2 Authentication-Results comment: %q", got)
	}
}
