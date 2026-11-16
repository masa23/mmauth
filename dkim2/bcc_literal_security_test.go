package dkim2

import "testing"

func TestBCCAddressLiteralSpellingsCannotBypassClassification(t *testing.T) {
	for _, test := range []struct {
		name      string
		bcc       string
		recipient string
	}{
		{"expanded IPv6", "<hidden@[IPv6:2001:db8::1]>", "<hidden@[ipv6:2001:0DB8:0000:0000:0000:0000:0000:0001]>"},
		{"metadata expanded IPv6", "<hidden@[IPv6:2001:0db8:0:0:0:0:0:1]>", "<hidden@[IPv6:2001:db8::1]>"},
		{"decimal IPv4 zeroes", "<hidden@[192.0.2.1]>", "<hidden@[192.000.002.001]>"},
		{"metadata decimal IPv4 zeroes", "<hidden@[192.000.002.001]>", "<hidden@[192.0.2.1]>"},
		{"IPv4-mapped IPv6", "<hidden@[192.0.2.1]>", "<hidden@[IPv6:::ffff:192.0.2.1]>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
				MailFrom: "<alice@example.com>", RcptTo: []string{test.recipient, "<visible@destination.test>"},
			}, Timestamp: testTime, BCCRecipients: []string{test.bcc}}
			if wire, err := Sign(original(), options); err == nil || wire != nil {
				t.Fatal("equivalent address literal exposed a BCC recipient")
			}
			options.Envelope.RcptTo = []string{test.recipient, "<other-blind@destination.test>"}
			options.BCCRecipients = append(options.BCCRecipients, "<other-blind@destination.test>")
			wire, err := Sign(original(), options)
			if err != nil {
				t.Fatalf("equivalent all-BCC copy rejected: %v", err)
			}
			parsed, err := Parse(wire)
			if err != nil || parsed.Signatures[0].Recipients[0] != test.recipient {
				t.Fatalf("classification changed authenticated path spelling: %v", err)
			}
		})
	}
}

func TestBCCAddressLiteralTypesRemainDistinct(t *testing.T) {
	for _, bcc := range []string{"<hidden@[192.0.2.1]>", "<hidden@[ip:192.0.2.1]>"} {
		options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
			MailFrom: "<alice@example.com>", RcptTo: []string{"<hidden@[192.0.2.1]>", "<hidden@[ip:192.0.2.1]>"},
		}, Timestamp: testTime, BCCRecipients: []string{bcc}}
		if wire, err := Sign(original(), options); err == nil || wire != nil {
			t.Fatal("IP and general address literal collided, exposing a BCC recipient")
		}
	}
}
