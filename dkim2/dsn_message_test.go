package dkim2

import (
	"bytes"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

func dsnMessageFixture(t *testing.T) ([]byte, Envelope, DSNOptions) {
	t.Helper()
	key := edKey()
	envelope := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: envelope, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options := DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Timestamp: testTime},
		Verify:       VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}, Now: testTime},
		ReportingMTA: "mx.relay.test", HumanText: "配信できませんでした。\n",
		Recipients: []DSNRecipient{{FinalRecipient: "<bob@relay.test>", Action: "failed", Status: "5.1.1", Diagnostic: "550 mailbox unavailable"}}}
	return wire, envelope, options
}

func TestCreateDSNThreePartsAndExactOriginal(t *testing.T) {
	original, incoming, options := dsnMessageFixture(t)
	for _, headersOnly := range []bool{false, true} {
		options.HeadersOnly = headersOnly
		generated, err := CreateDSN(original, incoming, options)
		if err != nil {
			t.Fatal(err)
		}
		if generated.Envelope.MailFrom != "<>" || len(generated.Envelope.RcptTo) != 1 || generated.Envelope.RcptTo[0] != incoming.MailFrom {
			t.Fatalf("unsafe return envelope: %+v", generated.Envelope)
		}
		if result := Verify(generated.Wire, generated.Envelope, options.Verify); result.Status != Pass {
			t.Fatalf("DSN authentication failed: %+v", result)
		}
		parsed, err := parseDSN(generated.Wire)
		if err != nil {
			t.Fatal(err)
		}
		wantOriginal := original
		if headersOnly {
			wantOriginal = original[:bytes.Index(original, []byte("\r\n\r\n"))+2]
		}
		if !bytes.Equal(parsed.original, wantOriginal) || parsed.headersOnly != headersOnly || parsed.humanText != "配信できませんでした。\r\n" || parsed.reportingMTA != options.ReportingMTA || len(parsed.recipients) != 1 || parsed.recipients[0] != options.Recipients[0] {
			t.Fatalf("report roundtrip changed content: %+v", parsed)
		}
	}
}

func TestCreateDSNRequiresActualAuthenticatedDelivery(t *testing.T) {
	original, incoming, options := dsnMessageFixture(t)
	tests := []struct {
		name   string
		change func(*DSNOptions)
	}{
		{"unrelated signer", func(o *DSNOptions) { o.Sign.Domain = "unrelated.test" }},
		{"no statuses", func(o *DSNOptions) { o.Recipients = nil }},
		{"unrelated status recipient", func(o *DSNOptions) { o.Recipients[0].FinalRecipient = "<other@relay.test>" }},
		{"invalid action status", func(o *DSNOptions) { o.Recipients[0].Status = "3.1.1" }},
		{"injected diagnostic", func(o *DSNOptions) { o.Recipients[0].Diagnostic = "550 no\r\nBcc: leak" }},
		{"injected reporting mta", func(o *DSNOptions) { o.ReportingMTA = "mx.relay.test\r\nBcc: leak" }},
		{"explicit envelope", func(o *DSNOptions) { o.Sign.Envelope = incoming }},
		{"explicit next domain", func(o *DSNOptions) { o.Sign.NextDomain = "next.test" }},
		{"BCC declaration", func(o *DSNOptions) { o.Sign.BCCRecipients = []string{"<hidden@relay.test>"} }},
		{"initial exploded", func(o *DSNOptions) { o.Sign.Flags = []string{"exploded"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := options
			o.Recipients = append([]DSNRecipient(nil), options.Recipients...)
			test.change(&o)
			if generated, err := CreateDSN(original, incoming, o); err == nil || generated != nil {
				t.Fatal("unsafe DSN was generated")
			}
		})
	}
	tampered := bytes.Replace(original, []byte("hello\r\n"), []byte("altered\r\n"), 1)
	if _, err := CreateDSN(tampered, incoming, options); err == nil {
		t.Fatal("unauthenticated original generated a DSN")
	}
	key := edKey()
	nullEnvelope := Envelope{"<>", incoming.RcptTo}
	null, err := Sign(originalMessageForDSN(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: nullEnvelope, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateDSN(null, nullEnvelope, options); err == nil {
		t.Fatal("null reverse-path generated a DSN")
	}
}

func originalMessageForDSN() []byte { return []byte("From: alice@example.com\r\n\r\nhello\r\n") }

func TestDSNUTF8StatusRecipientUsesSevenBitEncoding(t *testing.T) {
	original, incoming, options := dsnMessageFixture(t)
	key := edKey()
	incoming.RcptTo = []string{"<受信者@relay.test>"}
	var err error
	original, err = Sign(originalMessageForDSN(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: incoming, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options.Recipients[0].FinalRecipient = incoming.RcptTo[0]
	generated, err := CreateDSN(original, incoming, options)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseDSN(generated.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.recipients[0].FinalRecipient != incoming.RcptTo[0] {
		t.Fatal("UTF-8 recipient identity changed")
	}
	status, err := buildDeliveryStatus(options.ReportingMTA, options.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range status {
		if b >= 128 {
			t.Fatal("delivery-status is not seven-bit safe")
		}
	}
}

func testDSNMultipart(t *testing.T, partTypes []string, machine string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for i, contentType := range partTypes {
		p, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {contentType}})
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("human-readable\r\n")
		if i == 1 {
			data = []byte(machine)
		}
		if i == 2 {
			data = originalMessageForDSN()
		}
		if _, err := p.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	value := mime.FormatMediaType("multipart/report", map[string]string{"boundary": w.Boundary(), "report-type": "delivery-status"})
	return append([]byte("From: postmaster@relay.test\r\nMIME-Version: 1.0\r\nContent-Type: "+value+"\r\n\r\n"), body.Bytes()...)
}

func TestParseDSNRejectsAmbiguousReports(t *testing.T) {
	const machine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; bob@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	valid := testDSNMultipart(t, []string{"text/plain", "message/delivery-status", "message/rfc822"}, machine)
	if _, err := parseDSN(valid); err != nil {
		t.Fatal(err)
	}
	// Human presentations do not affect machine-status authentication and
	// must never be recursively interpreted or copied to an upstream DSN.
	alternative := testDSNMultipart(t, []string{"multipart/alternative; boundary=human", "message/delivery-status", "message/rfc822"}, machine)
	alternative = bytes.Replace(alternative, []byte("human-readable\r\n"), []byte("--human\r\nContent-Type: text/plain\r\n\r\nDelivery failed.\r\n--human--\r\n"), 1)
	if _, err := parseDSN(alternative); err != nil {
		t.Fatalf("opaque alternative human presentation rejected: %v", err)
	}
	for _, wire := range [][]byte{
		append([]byte("Content-Type: multipart/report; boundary=other; report-type=delivery-status\r\n"), valid...),
		bytes.Replace(valid, []byte("Content-Type: message/rfc822"), []byte("Content-Type: message/rfc822\r\nContent-Type: text/plain"), 1),
		bytes.Replace(valid, []byte("Content-Type: message/rfc822"), []byte("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64"), 1),
		testDSNMultipart(t, []string{"text/plain", "message/delivery-status"}, machine),
		testDSNMultipart(t, []string{"text/plain", "message/delivery-status", "message/rfc822", "text/plain"}, machine),
		bytes.Replace(valid, []byte("Action: failed\r\n"), []byte("Action: failed\r\nAction: delivered\r\n"), 1),
		bytes.Replace(valid, []byte("Status: 5.1.1"), []byte("Status: 5.01.1"), 1),
		bytes.Replace(valid, []byte("Content-Type: text/plain"), []byte("Content-Type: application/octet-stream"), 1),
		bytes.Replace(valid, []byte("Reporting-MTA: dns; relay.test"), []byte("Reporting-MTA: dns; relay.test\r\nReporting-MTA: dns; other.test"), 1),
	} {
		if _, err := parseDSN(wire); err == nil {
			t.Fatal("ambiguous/malformed DSN accepted")
		}
	}
	boundaryStart := bytes.LastIndex(valid, []byte("\r\n--"))
	if _, err := parseDSN(valid[:boundaryStart]); err == nil {
		t.Fatal("unterminated MIME report accepted")
	}
}

func TestDSNUnitextRejectsInvalidEscapes(t *testing.T) {
	for _, input := range []string{`\x{D800}`, `\x{110000}`, `\x{Z1}`, `\x{1}`, `\x{1234567}`, `\evil`, "non ascii 受信者", "+"} {
		if _, err := decodeDSNUnitext(input); err == nil {
			t.Fatalf("invalid escape accepted: %q", input)
		}
	}
	for _, input := range []string{`\x{20}`, `\x{5C}`, `\x{53D7}`} {
		if _, err := decodeDSNUnitext(input); err != nil {
			t.Fatalf("valid escape rejected: %q: %v", input, err)
		}
	}
}

func FuzzParseDSN(f *testing.F) {
	globalStatus := []byte("Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 宛先不明\r\n")
	globalOriginal := []byte("From: 受信@example.com\r\n\r\nbody\xff\r\n")
	f.Add(internationalDSNWire(f, "message/global-delivery-status", "message/global", "base64", globalStatus, globalOriginal))
	f.Add(internationalDSNWire(f, "message/global-delivery-status", "message/global", "8bit", globalStatus, globalOriginal))
	f.Add(internationalDSNWire(f, "message/global-delivery-status", "message/global-headers", "quoted-printable", globalStatus, []byte("From: 受信@example.com\r\n")))
	f.Add([]byte("From: postmaster@relay.test\r\nContent-Type: multipart/report; boundary=x; report-type=delivery-status\r\n\r\n--x--\r\n"))
	f.Add([]byte("From: postmaster@relay.test\r\n\r\n"))
	f.Add([]byte("From: postmaster@relay.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; boundary=x; report-type=delivery-status\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nDelivery failed.\r\n--x\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; bob@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: alice@example.com\r\n\r\nbody\r\n\r\n--x--\r\n"))
	f.Fuzz(func(t *testing.T, wire []byte) { _, _ = parseDSN(wire) })
}

func TestDeliveryStatusActionClasses(t *testing.T) {
	for action, status := range map[string]string{"failed": "5.1.1", "delayed": "4.0.0", "delivered": "2.0.0", "relayed": "2.1.0", "expanded": "2.0.0"} {
		if !validDSNActionStatus(action, status) {
			t.Fatalf("valid %s/%s rejected", action, status)
		}
	}
	for _, action := range []string{"failed", "FAILED", "Delayed", "delivered", "relayed", "expanded"} {
		if !validDSNActionStatus(action, "4.4.7") {
			t.Fatalf("independent action/status rejected: %s", action)
		}
	}
	for _, status := range []string{"5.1", "5.1.1\r\nBcc: leak", "5.1000.1", "3.0.0", "55.1.1", "5.a.0", "5.01.1", "5.1.01"} {
		if validDSNActionStatus("failed", status) {
			t.Fatalf("invalid status %q accepted", status)
		}
	}
	if !strings.Contains(string(originalMessageForDSN()), "\r\n") {
		t.Fatal("fixture is not CRLF")
	}
}

func TestDeliveryStatusRFC3464CommentsAndCase(t *testing.T) {
	data := []byte("Reporting-MTA: (reporter) dns; MX.Relay.TEST\r\n\r\nFinal-Recipient: rfc822 (address type); \"Case(Inside)\"@Destination.TEST (outside)\r\nAction: FAILED (retry limit reached)\r\nStatus: 4.4.7 (delivery time expired)\r\n")
	reporting, recipients, err := parseDeliveryStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if reporting != "MX.Relay.TEST" || len(recipients) != 1 || recipients[0].FinalRecipient != `<"Case(Inside)"@Destination.TEST>` || recipients[0].Action != "failed" || recipients[0].Status != "4.4.7" {
		t.Fatalf("comments changed lexical values or mailbox case: %q %+v", reporting, recipients)
	}
	wire, err := buildDeliveryStatus("mx.relay.test", []DSNRecipient{{FinalRecipient: `<"Case(Inside)"@Destination.TEST>`, Action: "FAILED", Status: "4.4.7 (expired)"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`Final-Recipient: rfc822; "Case(Inside)"@Destination.TEST`)) {
		t.Fatal("builder changed mailbox case")
	}
	for _, value := range []string{"4.4.7 (unterminated", "4.4.7 (closed) trailing", "4.4.7 )", "4.(not legal here)4.7", "4.4.7 (" + strings.Repeat("(", 33) + strings.Repeat(")", 34)} {
		bad := bytes.Replace(data, []byte("4.4.7 (delivery time expired)"), []byte(value), 1)
		if _, _, err := parseDeliveryStatus(bad); err == nil {
			t.Fatalf("malformed comments accepted: %q", value)
		}
	}
}

func TestCreateDSNPreservesRecipientDomainCase(t *testing.T) {
	wire, incoming, options := dsnMessageFixture(t)
	incoming.RcptTo[0] = "<bob@RELAY.TEST>"
	before := options.Recipients[0].FinalRecipient
	generated, err := CreateDSN(wire, incoming, options)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseDSN(generated.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.recipients[0].FinalRecipient != incoming.RcptTo[0] {
		t.Fatal("recipient domain case was lost")
	}
	if options.Recipients[0].FinalRecipient != before {
		t.Fatal("caller delivery status was mutated")
	}
}

func TestDSNMIMEHeaderPreflightLimits(t *testing.T) {
	for _, header := range []string{
		"X:" + strings.Repeat("a", maxHeaderFieldBytes) + "\r\n",
		"X:a\r\n" + strings.Repeat(" a\r\n", maxHeaderFieldBytes/4),
		strings.Repeat("X:a\r\n", maxHeaderFields+1),
		strings.Repeat("X:"+strings.Repeat("a", maxHeaderFieldBytes-4)+"\r\n", maxHeaderBytes/maxHeaderFieldBytes) + "X:a\r\n",
	} {
		body := []byte("--x\r\n" + header + "\r\nbody\r\n--x--\r\n")
		if err := preflightDSNPartHeaders(body, "x"); err == nil {
			t.Fatal("oversized MIME header block passed preflight")
		}
	}
	for _, body := range []string{
		"preamble\r\n--x \t\r\nContent-Type: text/plain\r\n\r\nbody\r\n--x-- \t\r\nepilogue",
		"--x\r\nContent-Type: text/plain\r\n\r\n--x-not-a-boundary\r\n--x--",
	} {
		if err := preflightDSNPartHeaders([]byte(body), "x"); err != nil {
			t.Fatalf("valid boundary rejected: %v", err)
		}
	}
}
