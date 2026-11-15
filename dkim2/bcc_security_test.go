package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

func TestBCCRecipientsRequireSeparateSignedCopies(t *testing.T) {
	key := edKey()
	const visible = "<visible@destination.test>"
	const hidden = "<hidden@destination.test>"
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{visible, hidden},
	}, Timestamp: testTime, BCCRecipients: []string{"<hidden@DESTINATION.test>"}}
	if wire, err := Sign(original(), options); err == nil || wire != nil {
		t.Fatal("mixed BCC and ordinary recipients were signed")
	}
	for _, recipient := range []string{visible, hidden} {
		options.Envelope.RcptTo = []string{recipient}
		wire, err := Sign(original(), options)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(wire)
		if err != nil {
			t.Fatal(err)
		}
		if recipients := parsed.Signatures[0].Recipients; len(recipients) != 1 || recipients[0] != recipient {
			t.Fatalf("wrong recipients in signed copy: %v", recipients)
		}
		if recipient == visible && bytes.Contains(wire, []byte(hidden)) {
			t.Fatal("BCC metadata leaked into ordinary copy")
		}
		result := Verify(wire, options.Envelope, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime})
		if result.Status != Pass {
			t.Fatalf("split copy failed authentication: %+v", result)
		}
	}
	if options.BCCRecipients[0] != "<hidden@DESTINATION.test>" {
		t.Fatal("signing mutated caller BCC metadata")
	}
}

func TestBCCRecipientClassificationUsesMailboxSemantics(t *testing.T) {
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
		MailFrom: "<alice@example.com>",
	}, Timestamp: testTime}
	for _, recipients := range [][]string{
		{"<hidden@DESTINATION.test>", "<second@destination.test>"},
		{"<hidden@bücher.example>", "<second@destination.test>"},
	} {
		options.Envelope.RcptTo = recipients
		options.BCCRecipients = []string{"<hidden@destination.test>", "<hidden@xn--bcher-kva.example>", "<second@destination.test>"}
		if _, err := Sign(original(), options); err != nil {
			t.Fatalf("all-BCC delivery rejected after domain normalization: %v", err)
		}
	}
	options.Envelope.RcptTo = []string{"<Hidden@destination.test>", "<hidden@destination.test>"}
	options.BCCRecipients = []string{"<hidden@destination.test>"}
	if _, err := Sign(original(), options); err == nil {
		t.Fatal("case-sensitive local parts were merged, exposing a blind recipient")
	}
}

func TestBCCRecipientPathsAreValidated(t *testing.T) {
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<visible@destination.test>"},
	}, Timestamp: testTime}
	for _, recipient := range []string{"<>", "not-an-address", "<a@example.com>\r\nBcc: injected"} {
		options.BCCRecipients = []string{recipient}
		if _, err := Sign(original(), options); err == nil {
			t.Fatalf("invalid BCC metadata accepted: %q", recipient)
		}
	}
}

func TestBCCMailboxSpellingsCannotBypassClassification(t *testing.T) {
	for _, test := range []struct {
		name      string
		bcc       string
		recipient string
	}{
		{"quoted local", "<hidden@destination.test>", `<"hidden"@destination.test>`},
		{"quoted pairs", `<"h\id\den"@destination.test>`, "<hidden@destination.test>"},
		{"escaped quote", `<"hi\"dden"@destination.test>`, `<"h\i\"dden"@destination.test>`},
		{"source route", "<hidden@destination.test>", "<@relay.test,@other.test:hidden@destination.test>"},
		{"metadata source route", "<@relay.test:hidden@destination.test>", `<"hidden"@destination.test>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
				MailFrom: "<alice@example.com>", RcptTo: []string{test.recipient, "<visible@destination.test>"},
			}, Timestamp: testTime, BCCRecipients: []string{test.bcc}}
			if wire, err := Sign(original(), options); err == nil || wire != nil {
				t.Fatal("equivalent mailbox spelling exposed a BCC recipient")
			}
			options.Envelope.RcptTo = []string{test.recipient, "<other-blind@destination.test>"}
			options.BCCRecipients = append(options.BCCRecipients, "<other-blind@destination.test>")
			wire, err := Sign(original(), options)
			if err != nil {
				t.Fatalf("equivalent all-BCC copy rejected: %v", err)
			}
			parsed, err := Parse(wire)
			if err != nil || parsed.Signatures[0].Recipients[0] != test.recipient {
				t.Fatalf("mailbox classification changed authenticated path spelling: %v", err)
			}
		})
	}
}

// RFC 5321 Section 4.1.1.3 makes Postmaster case insensitive even when a
// domain is present. This exception applies after mailbox quote decoding.
func TestBCCPostmasterSpellingsCannotBypassClassification(t *testing.T) {
	for _, recipient := range []string{
		"<Postmaster@destination.test>",
		"<POSTMASTER@DESTINATION.test>",
		`<"Postmaster"@destination.test>`,
		`<"Po\stmaster"@destination.test>`,
		"<@relay.test:Postmaster@destination.test>",
	} {
		t.Run(recipient, func(t *testing.T) {
			options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
				MailFrom: "<alice@example.com>", RcptTo: []string{recipient, "<visible@destination.test>"},
			}, Timestamp: testTime, BCCRecipients: []string{"<postmaster@destination.test>"}}
			if wire, err := Sign(original(), options); err == nil || wire != nil {
				t.Fatal("Postmaster case variant exposed a BCC recipient")
			}
			options.Envelope.RcptTo = []string{recipient, "<other-blind@destination.test>"}
			options.BCCRecipients = append(options.BCCRecipients, "<other-blind@destination.test>")
			if _, err := Sign(original(), options); err != nil {
				t.Fatalf("all-BCC copy rejected: %v", err)
			}
		})
	}
}

func TestBCCPostmasterDomainsRemainDistinct(t *testing.T) {
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<Postmaster@destination.test>", "<postmaster@other.test>"},
	}, Timestamp: testTime, BCCRecipients: []string{"<postmaster@destination.test>"}}
	if wire, err := Sign(original(), options); err == nil || wire != nil {
		t.Fatal("Postmaster at different domains was merged, exposing a BCC recipient")
	}
}

func TestBCCPostmasterCaseExceptionIsASCIIOnly(t *testing.T) {
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<postmaster@destination.test>", "<poſtmaster@destination.test>"},
	}, Timestamp: testTime, BCCRecipients: []string{"<postmaster@destination.test>"}}
	if wire, err := Sign(original(), options); err == nil || wire != nil {
		t.Fatal("Unicode local part was treated as reserved Postmaster, exposing a BCC recipient")
	}
}

func TestBCCProtectionAppliesToForwardAndRevise(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: Envelope{
		MailFrom: "<bounce@relay.test>", RcptTo: []string{"<visible@destination.test>", "<hidden@destination.test>"},
	}, Timestamp: testTime, BCCRecipients: []string{"<hidden@destination.test>"}, OutOfBandArrangement: true}
	if _, err := Forward(first, options); err == nil {
		t.Fatal("Forward signed mixed BCC recipients")
	}
	modified := append(append([]byte(nil), first...), []byte("footer\r\n")...)
	if _, err := Revise(modified, []byte(`{"b":[{"c":[1,1]}]}`), options); err == nil {
		t.Fatal("Revise signed mixed BCC recipients")
	}
}

func TestSigningRejectsPopulatedBlindRecipientHeaders(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	firstOptions := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime}
	first, err := Sign(original(), firstOptions)
	if err != nil {
		t.Fatal(err)
	}
	nextOptions := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: Envelope{
		MailFrom: "<bounce@relay.test>", RcptTo: []string{"<visible@destination.test>"},
	}, Timestamp: testTime, OutOfBandArrangement: true}
	for _, header := range []string{"Bcc: hidden@destination.test\r\n", "rEsEnT-bCc:\r\n\thidden@destination.test\r\n"} {
		if _, err := Sign(append([]byte(header), original()...), firstOptions); err == nil {
			t.Fatal("Sign preserved populated blind-recipient field")
		}
		wire := append([]byte(header), first...)
		if _, err := Forward(wire, nextOptions); err == nil || !strings.Contains(err.Error(), "remove populated") {
			t.Fatalf("Forward did not reject populated blind-recipient field: %v", err)
		}
		if _, err := Revise(wire, []byte(`{"b":[{"c":[1,1]}]}`), nextOptions); err == nil || !strings.Contains(err.Error(), "remove populated") {
			t.Fatalf("Revise did not reject populated blind-recipient field: %v", err)
		}
	}
	if _, err := Sign(append([]byte("Bcc: \t\r\nResent-Bcc:\r\n"), original()...), firstOptions); err != nil {
		t.Fatalf("empty blind-recipient fields rejected: %v", err)
	}
}
