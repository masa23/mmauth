package dkim2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type dsnFixture struct {
	incoming, outgoing  Envelope
	original, forwarded []byte
	resolver            records
	notification        DSNOptions
}

func newDSNFixture(t *testing.T, nullBody bool) dsnFixture {
	t.Helper()
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
	r := records{
		"s1._domainkey.example.com":      {keyRecord(key)},
		"s2._domainkey.relay.test":       {keyRecord(key)},
		"s3._domainkey.destination.test": {keyRecord(key)},
		"s4._domainkey.unrelated.test":   {keyRecord(key)},
	}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Replace(first, []byte("Subject: original"), []byte("Subject: revised"), 1)
	modified = append(modified, []byte("downstream footer\r\n")...)
	recipe := []byte(`{"h":{"subject":[{"d":[" original"]}]},"b":[{"c":[1,1]}]}`)
	if nullBody {
		recipe = []byte(`{"h":{"subject":[{"d":[" original"]}]},"b":null}`)
	}
	forwarded, err := ReviseChecked(first, modified, in, VerifyOptions{Resolver: r, Now: testTime}, recipe, SignOptions{
		Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime, AllowNullBodyRecipe: nullBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	forwarded = append([]byte("Received: private-route.destination.test\r\nX-Private: destination.test\r\n"), forwarded...)
	return dsnFixture{in, out, first, forwarded, r, DSNOptions{
		Sign:       SignOptions{Domain: "destination.test", Selector: "s3", Key: key, Timestamp: testTime},
		Verify:     VerifyOptions{Resolver: r, Now: testTime},
		HumanText:  "Delivery to carol@destination.test failed.\r\n",
		Recipients: []DSNRecipient{{FinalRecipient: out.RcptTo[0], Action: "failed", Status: "5.1.1", Diagnostic: "550 unknown user"}},
	}}
}

func (f dsnFixture) report(t *testing.T) *GeneratedDSN {
	t.Helper()
	message, err := CreateDSN(f.forwarded, f.outgoing, f.notification)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestDSNEndToEndAndPrivatePropagation(t *testing.T) {
	f := newDSNFixture(t, false)
	for _, headersOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "headers-only"}[headersOnly], func(t *testing.T) {
			f.notification.HeadersOnly = headersOnly
			report := f.report(t)
			verification := DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}
			result := VerifyDSN(report.Wire, report.Envelope, verification)
			if result.Status != Pass || result.HeadersOnly != headersOnly {
				t.Fatalf("DSN verification: %+v", result)
			}
			if result.ReportingMTA != "destination.test" || len(result.Recipients) != 1 || result.Recipients[0].Action != "failed" || result.Recipients[0].Status != "5.1.1" {
				t.Fatalf("authenticated recipient status not returned: %+v", result)
			}
			upstream, err := PropagateDSN(report.Wire, report.Envelope, DSNPropagationOptions{
				Verification: verification, ReceivedSignatureIndex: 1,
				Notification: DSNOptions{
					Sign:      SignOptions{Domain: "relay.test", Selector: "s2", Key: edKey(), Timestamp: testTime},
					HumanText: "Delivery failed.\r\n", Recipients: []DSNRecipient{{FinalRecipient: f.incoming.RcptTo[0], Action: "failed", Status: "5.0.0"}},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if upstream.Envelope.MailFrom != "<>" || len(upstream.Envelope.RcptTo) != 1 || upstream.Envelope.RcptTo[0] != f.incoming.MailFrom {
				t.Fatalf("bad upstream envelope: %+v", upstream.Envelope)
			}
			if bytes.Contains(upstream.Wire, []byte("destination.test")) || bytes.Contains(upstream.Wire, []byte("downstream footer")) {
				t.Fatal("downstream routing or content leaked upstream")
			}
			checked := VerifyDSN(upstream.Wire, upstream.Envelope, DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"example.com"}})
			if checked.Status != Pass || checked.HeadersOnly != headersOnly {
				t.Fatalf("upstream verification: %+v", checked)
			}
			parsed, err := Parse(checked.Original)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 1 || len(parsed.Instances) != 1 {
				t.Fatal("outward DKIM2 fields survived reconstruction")
			}
			if !bytes.Contains(bytes.ToLower(checked.Original), []byte("subject: original\r\n")) {
				t.Fatal("original header not restored")
			}
			if !headersOnly && string(parsed.Body) != "hello\r\n" {
				t.Fatalf("original body=%q", parsed.Body)
			}
		})
	}
}

func TestDSNNullRecipePropagatesHeadersOnly(t *testing.T) {
	f := newDSNFixture(t, true)
	report := f.report(t)
	upstream, err := PropagateDSN(report.Wire, report.Envelope, DSNPropagationOptions{
		Verification: DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}, ReceivedSignatureIndex: 1,
		Notification: DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: edKey(), Timestamp: testTime}, Recipients: []DSNRecipient{{FinalRecipient: f.incoming.RcptTo[0], Action: "failed", Status: "5.0.0"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyDSN(upstream.Wire, upstream.Envelope, DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"example.com"}})
	if result.Status != Pass || !result.HeadersOnly {
		t.Fatalf("null recipe result: %+v", result)
	}
	if bytes.Contains(result.Original, []byte("hello")) || bytes.Contains(result.Original, []byte("footer")) {
		t.Fatal("unrecoverable body was returned")
	}
}

func TestDSNVerificationRejectsForgery(t *testing.T) {
	f := newDSNFixture(t, false)
	report := f.report(t)
	options := DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}
	for _, tc := range []struct {
		name     string
		wire     []byte
		envelope Envelope
		options  DSNVerifyOptions
	}{
		{"tampered outer", bytes.Replace(report.Wire, []byte("Delivery to"), []byte("Altered to"), 1), report.Envelope, options},
		{"not local", report.Wire, report.Envelope, DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"unrelated.test"}}},
		{"missing identity", report.Wire, report.Envelope, DSNVerifyOptions{Verification: f.notification.Verify}},
		{"wrong recipient", report.Wire, Envelope{"<>", []string{"<someone@relay.test>"}}, options},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := VerifyDSN(tc.wire, tc.envelope, tc.options); r.Status == Pass {
				t.Fatalf("forgery accepted: %+v", r)
			}
		})
	}
	// A legitimately signed report does not authenticate a forged embedded
	// signature, and a legitimate but unrelated reporter cannot file this DSN.
	for _, kind := range []string{"forged original", "wrong origin", "nonnull sender"} {
		t.Run(kind, func(t *testing.T) {
			original := append([]byte(nil), f.forwarded...)
			notification := f.notification
			if kind == "forged original" {
				m, _ := Parse(original)
				old := m.Signatures[len(m.Signatures)-1].Values[0].Value
				original = bytes.Replace(original, []byte(foldBase64(old)), []byte(foldBase64(base64.StdEncoding.EncodeToString(make([]byte, 64)))), 1)
			}
			if kind == "wrong origin" {
				notification.Sign.Domain = "unrelated.test"
				notification.Sign.Selector = "s4"
			}
			forged, err := buildDSN(original, report.Envelope, notification)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "nonnull sender" {
				m, _ := Parse(forged.Wire)
				var unsigned strings.Builder
				for _, field := range m.Headers {
					name, _, _ := strings.Cut(field, ":")
					if !strings.EqualFold(name, "DKIM2-Signature") && !strings.EqualFold(name, "Message-Instance") {
						unsigned.WriteString(field)
					}
				}
				unsigned.WriteString("\r\n")
				unsigned.Write(m.Body)
				forged.Envelope.MailFrom = "<bounce@destination.test>"
				forged.Wire, err = Sign([]byte(unsigned.String()), SignOptions{Domain: "destination.test", Selector: "s3", Key: edKey(), Envelope: forged.Envelope, Timestamp: testTime})
				if err != nil {
					t.Fatal(err)
				}
			}
			if result := VerifyDSN(forged.Wire, forged.Envelope, options); result.Status == Pass {
				t.Fatalf("accepted %s", kind)
			}
		})
	}
}

func TestDSNVerificationDNSBudgetsAndFailures(t *testing.T) {
	f := newDSNFixture(t, false)
	report := f.report(t)
	options := DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}
	options.Verification.MaxDNSLookups = 1
	if result := VerifyDSN(report.Wire, report.Envelope, options); result.Status != PermError || !errors.Is(result.Err, errDNSLookupBudget) {
		t.Fatalf("aggregate budget: %+v", result)
	}
	options.Verification = f.notification.Verify
	delete(f.resolver, "s2._domainkey.relay.test")
	if result := VerifyDSN(report.Wire, report.Envelope, options); result.Status != PermError {
		t.Fatalf("missing original key: %+v", result)
	}
	options.Verification.Resolver = dnsFailure{}
	if result := VerifyDSN(report.Wire, report.Envelope, options); result.Status != TempError {
		t.Fatalf("temporary DNS: %+v", result)
	}
}

func TestDSNPropagationRejectsBadCutoffAndDisclosure(t *testing.T) {
	f := newDSNFixture(t, false)
	report := f.report(t)
	options := DSNPropagationOptions{Verification: DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}, ReceivedSignatureIndex: 1,
		Notification: DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: edKey(), Timestamp: testTime}, Recipients: []DSNRecipient{{FinalRecipient: f.incoming.RcptTo[0], Action: "failed", Status: "5.0.0"}}}}
	for _, cutoff := range []int{-1, 0, 2, 999} {
		bad := options
		bad.ReceivedSignatureIndex = cutoff
		if _, err := PropagateDSN(report.Wire, report.Envelope, bad); err == nil {
			t.Fatalf("cutoff %d accepted", cutoff)
		}
	}
	options.Notification.Recipients = []DSNRecipient{{FinalRecipient: f.outgoing.RcptTo[0], Action: "failed", Status: "5.1.1"}}
	if _, err := PropagateDSN(report.Wire, report.Envelope, options); err == nil {
		t.Fatal("downstream status recipient leaked")
	}
}

func TestDSNPropagationRemovesImaginaryHops(t *testing.T) {
	f := newDSNFixture(t, false)
	key := edKey()
	firstHop, err := Forward(f.original, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, NextDomain: "relay-out.test", Timestamp: testTime, OutOfBandArrangement: true})
	if err != nil {
		t.Fatal(err)
	}
	outgoing := Envelope{"<bounce@relay-out.test>", f.outgoing.RcptTo}
	forwarded, err := Forward(firstHop, SignOptions{Domain: "relay-out.test", Selector: "s5", Key: key, Envelope: outgoing, Timestamp: testTime, OutOfBandArrangement: true})
	if err != nil {
		t.Fatal(err)
	}
	f.resolver["s5._domainkey.relay-out.test"] = []string{keyRecord(key)}
	report, err := CreateDSN(forwarded, outgoing, f.notification)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := PropagateDSN(report.Wire, report.Envelope, DSNPropagationOptions{
		Verification:           DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test", "relay-out.test"}},
		ReceivedSignatureIndex: 1,
		Notification:           DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Timestamp: testTime}, Recipients: []DSNRecipient{{FinalRecipient: f.incoming.RcptTo[0], Action: "failed", Status: "5.0.0"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(upstream.Wire, []byte("relay-out.test")) || bytes.Contains(upstream.Wire, []byte("destination.test")) {
		t.Fatal("imaginary or downstream hop exposed")
	}
	if result := VerifyDSN(upstream.Wire, upstream.Envelope, DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"example.com"}}); result.Status != Pass {
		t.Fatalf("upstream: %+v", result)
	}
}

func TestDSNPropagationAuthenticatesPreviousReturnAddress(t *testing.T) {
	f := newDSNFixture(t, false)
	report := f.report(t)
	delete(f.resolver, "s1._domainkey.example.com")
	verification := DSNVerifyOptions{Verification: f.notification.Verify, LocalDomains: []string{"relay.test"}}
	if result := VerifyDSN(report.Wire, report.Envelope, verification); result.Status != Pass {
		t.Fatalf("DSN itself should remain authentic: %+v", result)
	}
	_, err := PropagateDSN(report.Wire, report.Envelope, DSNPropagationOptions{
		Verification: verification, ReceivedSignatureIndex: 1,
		Notification: DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: edKey(), Timestamp: testTime}, Recipients: []DSNRecipient{{FinalRecipient: f.incoming.RcptTo[0], Action: "failed", Status: "5.0.0"}}},
	})
	if err == nil {
		t.Fatal("unverified predecessor's return address used for propagation")
	}
}
