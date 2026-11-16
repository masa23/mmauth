package dkim2

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"testing"
)

// TestCreateInternationalDSNAttachment proves that encapsulated UTF-8 uses the
// RFC 6533 type and preserves every original octet after transfer decoding.
func TestCreateInternationalDSNAttachment(t *testing.T) {
	for _, headersOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "headers-only"}[headersOnly], func(t *testing.T) {
			_, incoming, options := dsnMessageFixture(t)
			incoming.MailFrom = "<δοκιμή@example.com>"
			incoming.RcptTo = []string{"<受信@relay.test>"}
			original := []byte("From: δοκιμή@example.com\r\nTo: 受信@relay.test\r\nSubject: 国際化\r\n\r\nbody\xff\r\n")
			signed, err := Sign(original, SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: incoming, Timestamp: testTime})
			if err != nil {
				t.Fatal(err)
			}
			options.HeadersOnly = headersOnly
			options.Recipients[0].FinalRecipient = incoming.RcptTo[0]
			generated, err := CreateDSN(signed, incoming, options)
			if err != nil {
				t.Fatal(err)
			}
			message, err := Parse(generated.Wire)
			if err != nil {
				t.Fatal(err)
			}
			value, err := dsnSingleHeader(message.Headers, "Content-Type", true)
			if err != nil {
				t.Fatal(err)
			}
			_, params, err := mime.ParseMediaType(value)
			if err != nil {
				t.Fatal(err)
			}
			r := multipart.NewReader(bytes.NewReader(message.Body), params["boundary"])
			var third *multipart.Part
			for i := 0; i < 3; i++ {
				third, err = r.NextRawPart()
				if err != nil {
					t.Fatal(err)
				}
				if i < 2 {
					if err := third.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			wantType := "message/global"
			want := signed
			if headersOnly {
				wantType = "message/global-headers"
				want = signed[:bytes.Index(signed, []byte("\r\n\r\n"))+2]
			}
			if third.Header.Get("Content-Type") != wantType || third.Header.Get("Content-Transfer-Encoding") != "base64" {
				t.Fatalf("international attachment labels: %+v", third.Header)
			}
			encoded, err := io.ReadAll(third)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range bytes.Split(encoded, []byte("\r\n")) {
				if len(line) > 76 {
					t.Fatal("base64 output exceeds MIME line length")
				}
			}
			decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding.Strict(), bytes.NewReader(encoded)))
			if err != nil || !bytes.Equal(decoded, want) {
				t.Fatalf("original octets changed: %v", err)
			}
			got := VerifyDSN(generated.Wire, generated.Envelope, DSNVerifyOptions{Verification: options.Verify, LocalDomains: []string{"example.com"}})
			if got.Status != Pass || got.HeadersOnly != headersOnly || !bytes.Equal(got.Original, want) {
				t.Fatalf("international DSN verification: %+v", got)
			}
		})
	}
}

// TestInternationalDSNBodyClassification covers MIME descendants without
// recursively interpreting attacker-controlled nested MIME structures.
func TestInternationalDSNBodyClassification(t *testing.T) {
	for _, body := range []string{"受信\r\n", "--inner\r\nContent-Disposition: attachment; filename=\"受信.txt\"\r\n\r\ncontent\r\n--inner--\r\n"} {
		for _, headersOnly := range []bool{false, true} {
			_, incoming, options := dsnMessageFixture(t)
			message := []byte("From: alice@example.com\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" + body)
			signed, err := Sign(message, SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: incoming, Timestamp: testTime})
			if err != nil {
				t.Fatal(err)
			}
			options.HeadersOnly = headersOnly
			report, err := CreateDSN(signed, incoming, options)
			if err != nil {
				t.Fatal(err)
			}
			wantType := "message/global"
			if headersOnly {
				wantType = "text/rfc822-headers"
			}
			if !bytes.Contains(report.Wire, []byte("Content-Type: "+wantType+"\r\n")) {
				t.Fatalf("wrong content classification: headersOnly=%v", headersOnly)
			}
			if got := VerifyDSN(report.Wire, report.Envelope, DSNVerifyOptions{Verification: options.Verify, LocalDomains: []string{"example.com"}}); got.Status != Pass {
				t.Fatalf("body classification authentication failed: %+v", got)
			}
		}
	}
}

// internationalDSNWire builds independent MIME representations for parser tests.
func internationalDSNWire(t testing.TB, statusType, originalType, encoding string, machine, original []byte) []byte {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for i, contentType := range []string{"text/plain", statusType, originalType} {
		transfer := "7bit"
		data := []byte("Delivery failed.\r\n")
		if i == 1 {
			data, transfer = machine, encoding
		}
		if i == 2 {
			data, transfer = original, encoding
			if strings.Contains(contentType, "global") && transfer == "7bit" {
				transfer = "8bit"
			}
		}
		if contentType == "message/rfc822" {
			transfer = "8bit"
		}
		part, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {contentType}, "Content-Transfer-Encoding": {transfer}})
		if err != nil {
			t.Fatal(err)
		}
		switch transfer {
		case "base64":
			encoder := base64.NewEncoder(base64.StdEncoding, part)
			if _, err := encoder.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
		case "quoted-printable":
			encoder := quotedprintable.NewWriter(part)
			encoder.Binary = true
			if _, err := encoder.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
		default:
			if _, err := part.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, subtype, _ := strings.Cut(statusType, "/")
	value := mime.FormatMediaType("multipart/report", map[string]string{"boundary": w.Boundary(), "report-type": subtype})
	return append([]byte("From: postmaster@relay.test\r\nMIME-Version: 1.0\r\nContent-Type: "+value+"\r\n\r\n"), body.Bytes()...)
}

// TestInternationalDSNMediaCombinations verifies the traditional and global
// forms are interchangeable in their respective RFC 6533 multipart/report slots.
func TestInternationalDSNMediaCombinations(t *testing.T) {
	const asciiMachine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; bob@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	const globalMachine = "Reporting-MTA: dns; relay.test\r\nX-Report: 国際化\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 宛先不明\r\nLocalized-Diagnostic: ja; 宛先不明\r\nLocalized-Diagnostic: en; Unknown recipient\r\n"
	for _, statusType := range []string{"message/delivery-status", "message/global-delivery-status"} {
		encodings := []string{"7bit"}
		machine := []byte(asciiMachine)
		if statusType == "message/global-delivery-status" {
			encodings, machine = []string{"8bit", "base64", "quoted-printable"}, []byte(globalMachine)
		}
		for _, originalType := range []string{"message/rfc822", "text/rfc822-headers", "message/global", "message/global-headers"} {
			for _, encoding := range encodings {
				t.Run(statusType+"/"+originalType+"/"+encoding, func(t *testing.T) {
					original := []byte("From: alice@example.com\r\n\r\nbody\r\n")
					if strings.Contains(originalType, "global") {
						original = []byte("From: δοκιμή@example.com\r\n\r\nbody\xff\r\n")
					}
					headersOnly := strings.HasSuffix(originalType, "headers")
					if headersOnly {
						original = original[:bytes.Index(original, []byte("\r\n\r\n"))+2]
					}
					wire := internationalDSNWire(t, statusType, originalType, encoding, machine, original)
					got, err := parseDSN(wire)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got.original, original) || got.headersOnly != headersOnly {
						t.Fatal("original representation changed")
					}
					if statusType == "message/global-delivery-status" && (got.recipients[0].FinalRecipient != "<受信@relay.test>" || got.recipients[0].Diagnostic != "550 宛先不明") {
						t.Fatalf("international machine data changed: %+v", got.recipients)
					}
				})
			}
		}
	}
}

// TestGlobalDSNRecipientSpelling preserves native Unicode whitespace and SMTP
// quoted local parts while also accepting RFC 6533's transitional unitext form.
func TestGlobalDSNRecipientSpelling(t *testing.T) {
	for _, address := range []string{"受信@relay.test", "δοκιμή+tag=one@relay.test", "\u00a0受信\u00a0@relay.test", `"受信 空白"@relay.test`, `"\x{41}"@relay.test`, `"\x{0041}"@relay.test`, `\x{53D7}\x{4FE1}@relay.test`} {
		machine := []byte("Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; " + address + "\r\nAction: failed\r\nStatus: 5.1.1\r\n")
		got, err := parseDSN(internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "8bit", machine, originalMessageForDSN()))
		if err != nil {
			t.Fatalf("%q: %v", address, err)
		}
		want := address
		if strings.HasPrefix(address, `\x{`) {
			want = "受信@relay.test"
		}
		if got.recipients[0].FinalRecipient != "<"+want+">" {
			t.Fatalf("recipient spelling changed: %q", got.recipients[0].FinalRecipient)
		}
	}
}

// TestInternationalDSNMIMEBase64Whitespace accepts transport-inserted MIME
// whitespace without changing the strict base64 rules for signature tags.
func TestInternationalDSNMIMEBase64Whitespace(t *testing.T) {
	machine := []byte("Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n")
	original := []byte("From: 受信@example.com\r\n\r\nbody\xff\r\n")
	wire := internationalDSNWire(t, "message/global-delivery-status", "message/global", "base64", machine, original)
	for _, data := range [][]byte{machine, original} {
		encoded := base64.StdEncoding.EncodeToString(data)
		wire = bytes.Replace(wire, []byte(encoded), []byte(encoded[:8]+" \t\r\n"+encoded[8:]), 1)
	}
	got, err := parseDSN(wire)
	if err != nil || !bytes.Equal(got.original, original) {
		t.Fatalf("MIME whitespace decoding failed: %v", err)
	}
}

// TestInternationalDSNLocalizedDiagnostics accepts folded localized fields and
// distinct language tags while rejecting a repeated tag regardless of case.
func TestInternationalDSNLocalizedDiagnostics(t *testing.T) {
	const machine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 宛先不明\r\nLocalized-Diagnostic:\r\n ja;\r\n 宛先不明\r\nLocalized-Diagnostic: en; Unknown recipient\r\n"
	wire := internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "base64", []byte(machine), originalMessageForDSN())
	if _, err := parseDSN(wire); err != nil {
		t.Fatalf("folded localized diagnostic rejected: %v", err)
	}
	for _, bad := range []string{
		machine + "Localized-Diagnostic: JA; Duplicate\r\n",
		machine + "Localized-Diagnostic: ; Missing language\r\n",
		machine + "Localized-Diagnostic: en; Duplicate\r\n",
		strings.Replace(machine, "Diagnostic-Code: smtp; 550 宛先不明\r\n", "", 1),
	} {
		wire := internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "base64", []byte(bad), originalMessageForDSN())
		if _, err := parseDSN(wire); err == nil {
			t.Fatal("invalid localized diagnostic accepted")
		}
	}
}

// TestDSNUnitextCodePointGrammar prevents an encoded mailbox from being
// rewritten through escapes that RFC 6533's HEXPOINT production does not allow.
func TestDSNUnitextCodePointGrammar(t *testing.T) {
	for _, value := range []string{`\x{00}`, `\x{41}`, `\x{7E}`, `\x{000080}`, `\x{080}`, `\x{DFFF}`, `\x{110000}`} {
		if _, err := decodeDSNUnitext(value); err == nil {
			t.Fatalf("invalid HEXPOINT accepted: %q", value)
		}
	}
	for _, value := range []string{`\x{20}`, `\x{2B}`, `\x{3D}`, `\x{5C}`, `\x{7F}`, `\x{80}`, `\x{53D7}`, `\x{10FFFF}`} {
		if _, err := decodeDSNUnitext(value); err != nil {
			t.Fatalf("valid HEXPOINT rejected: %q: %v", value, err)
		}
	}
}

// TestGlobalDSNControlTokensRemainASCII prevents Unicode case folding from
// turning invalid protocol keywords into an accepted ASCII action or type.
func TestGlobalDSNControlTokensRemainASCII(t *testing.T) {
	const machine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 宛先不明\r\n"
	for _, bad := range []string{
		strings.Replace(machine, "Action: failed", "Action: faİled", 1),
		strings.Replace(machine, "Reporting-MTA: dns", "Reporting-MTA: dnſ", 1),
		strings.Replace(machine, "Diagnostic-Code: smtp", "Diagnostic-Code: ſmtp", 1),
	} {
		wire := internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "base64", []byte(bad), originalMessageForDSN())
		if _, err := parseDSN(wire); err == nil {
			t.Fatal("non-ASCII status keyword accepted")
		}
	}
	valid := internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "8bit", []byte(machine), originalMessageForDSN())
	for _, bad := range [][]byte{
		bytes.Replace(valid, []byte("report-type=global-delivery-status"), []byte("report-type=\"global-delİvery-status\""), 1),
		bytes.Replace(valid, []byte("Content-Transfer-Encoding: 8bit"), []byte("Content-Transfer-Encoding: 8bİt"), 1),
		append([]byte("Content-Transfer-Encoding: bİnary\r\n"), valid...),
	} {
		if _, err := parseDSN(bad); err == nil {
			t.Fatal("non-ASCII MIME control token accepted")
		}
	}
	_, incoming, options := dsnMessageFixture(t)
	options.Recipients[0].Action = "faİled"
	if _, err := buildDeliveryStatus(options.ReportingMTA, options.Recipients); err == nil {
		t.Fatal("builder accepted a non-ASCII action")
	}
	options.Recipients[0].Action = "failed"
	options.Recipients[0].FinalRecipient = incoming.RcptTo[0]
	options.Recipients[0].Diagnostic = "550 \xff"
	if _, err := buildDeliveryStatus(options.ReportingMTA, options.Recipients); err == nil {
		t.Fatal("builder accepted malformed UTF-8 diagnostic")
	}
}

// TestCreateDSNGlobalDiagnostic selects global status only when its text needs
// UTF-8; ordinary ASCII reports keep the existing delivery-status format.
func TestCreateDSNGlobalDiagnostic(t *testing.T) {
	original, incoming, options := dsnMessageFixture(t)
	options.Recipients[0].Diagnostic = "550 宛先不明"
	report, err := CreateDSN(original, incoming, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(report.Wire, []byte("report-type=global-delivery-status")) || !bytes.Contains(report.Wire, []byte("Content-Type: message/global-delivery-status\r\n")) {
		t.Fatal("UTF-8 diagnostic was not labeled global")
	}
	got := VerifyDSN(report.Wire, report.Envelope, DSNVerifyOptions{Verification: options.Verify, LocalDomains: []string{"example.com"}})
	if got.Status != Pass || got.Recipients[0].Diagnostic != options.Recipients[0].Diagnostic {
		t.Fatalf("UTF-8 diagnostic failed: %+v", got)
	}
}

// TestGlobalDSNAmbiguousNativeQuotedPair uses unitext when a native quoted
// local-part could otherwise be mistaken for an embedded Unicode escape.
func TestGlobalDSNAmbiguousNativeQuotedPair(t *testing.T) {
	_, incoming, options := dsnMessageFixture(t)
	incoming.RcptTo = []string{`<"受信\x{53D7}"@relay.test>`}
	original, err := Sign(originalMessageForDSN(), SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: incoming, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options.Recipients[0].FinalRecipient = incoming.RcptTo[0]
	options.Recipients[0].Diagnostic = "550 宛先不明"
	report, err := CreateDSN(original, incoming, options)
	if err != nil {
		t.Fatal(err)
	}
	got := VerifyDSN(report.Wire, report.Envelope, DSNVerifyOptions{Verification: options.Verify, LocalDomains: []string{"example.com"}})
	if got.Status != Pass || got.Recipients[0].FinalRecipient != incoming.RcptTo[0] {
		t.Fatalf("ambiguous quoted mailbox changed: %+v", got)
	}
}

// TestInternationalDSNRejectsMalformedData preserves transfer-decoding bounds,
// Unicode validity, MIME-type invariants and legacy machine-part restrictions.
func TestInternationalDSNRejectsMalformedData(t *testing.T) {
	const machine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: utf-8; 受信@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	const asciiMachine = "Reporting-MTA: dns; relay.test\r\n\r\nFinal-Recipient: rfc822; bob@relay.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"
	valid := internationalDSNWire(t, "message/global-delivery-status", "message/global-headers", "8bit", []byte(machine), []byte("From: 受信@example.com\r\n"))
	for _, wire := range [][]byte{
		bytes.Replace(valid, []byte("report-type=global-delivery-status"), []byte("report-type=delivery-status"), 1),
		bytes.Replace(valid, []byte("Content-Type: message/global-delivery-status"), []byte("Content-Type: message/global-delivery-status; charset=utf-8"), 1),
		bytes.Replace(valid, []byte("Content-Type: message/global-headers"), []byte("Content-Type: message/global-headers; charset=utf-8"), 1),
		internationalDSNWire(t, "message/global-delivery-status", "message/global-headers", "base64", []byte(strings.Replace(machine, "受信", "\xff", 1)), []byte("From: a@example.com\r\n")),
		internationalDSNWire(t, "message/global-delivery-status", "message/global-headers", "base64", []byte(machine), []byte("From: \xff@example.com\r\n")),
		internationalDSNWire(t, "message/global-delivery-status", "message/global-headers", "8bit", []byte(machine), []byte("From: 受信@example.com\r\n\r\nbody\r\n")),
		internationalDSNWire(t, "message/global-delivery-status", "message/global", "8bit", []byte(machine), []byte("From: \xff@example.com\r\n\r\nbody\r\n")),
		internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "8bit", []byte(machine), []byte("From: 受信@example.com\r\n\r\nbody\r\n")),
		internationalDSNWire(t, "message/global-delivery-status", "text/rfc822-headers", "8bit", []byte(machine), []byte("From: 受信@example.com\r\n")),
		internationalDSNWire(t, "message/delivery-status", "message/rfc822", "7bit", []byte(machine), originalMessageForDSN()),
		internationalDSNWire(t, "message/delivery-status", "message/rfc822", "base64", []byte(asciiMachine), originalMessageForDSN()),
		internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "8bit", []byte(strings.Replace(machine, "utf-8", "rfc822", 1)), originalMessageForDSN()),
		internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "8bit", []byte(machine+"Diagnostic-Code: smtp; 550 fail\r\nLocalized-Diagnostic: ja; 宛先不明\r\nLocalized-Diagnostic: JA; Duplicate\r\n"), originalMessageForDSN()),
		internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", "base64", []byte("X:"+strings.Repeat("a", maxDSNTextBytes)), originalMessageForDSN()),
	} {
		if _, err := parseDSN(wire); err == nil {
			t.Fatal("malformed international DSN accepted")
		}
	}
	for _, encoding := range []string{"7bit", "binary", ""} {
		wire := internationalDSNWire(t, "message/global-delivery-status", "message/rfc822", encoding, []byte(machine), originalMessageForDSN())
		if _, err := parseDSN(wire); err == nil {
			t.Fatalf("invalid global status CTE %q accepted", encoding)
		}
	}
	for _, originalType := range []string{"message/rfc822", "message/global"} {
		wire := internationalDSNWire(t, "message/global-delivery-status", originalType, "8bit", []byte(machine), []byte("From: alice@example.com\r\n\r\n\xff\x80\r\n"))
		if _, err := parseDSN(wire); err != nil {
			t.Fatalf("binary body rejected under %s: %v", originalType, err)
		}
	}
}

// TestInternationalDSNPropagation restores an authenticated international
// original and preserves the global attachment through a new upstream report.
func TestInternationalDSNPropagation(t *testing.T) {
	key := edKey()
	incoming := Envelope{"<δοκιμή@example.com>", []string{"<受信@relay.test>"}}
	outgoing := Envelope{"<返送@relay.test>", []string{"<宛先@destination.test>"}}
	r := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}, "s3._domainkey.destination.test": {keyRecord(key)}}
	v := VerifyOptions{Resolver: r, Now: testTime}
	first, err := Sign([]byte("From: δοκιμή@example.com\r\nTo: 受信@relay.test\r\nSubject: 国際化\r\n\r\n本文\r\n"), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: incoming, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := ForwardChecked(first, incoming, v, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: outgoing, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	report, err := CreateDSN(forwarded, outgoing, DSNOptions{Sign: SignOptions{Domain: "destination.test", Selector: "s3", Key: key, Timestamp: testTime}, Verify: v, Recipients: []DSNRecipient{{FinalRecipient: outgoing.RcptTo[0], Action: "failed", Status: "5.1.1", Diagnostic: "550 宛先不明"}}})
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := PropagateDSN(report.Wire, report.Envelope, DSNPropagationOptions{Verification: DSNVerifyOptions{Verification: v, LocalDomains: []string{"relay.test"}}, ReceivedSignatureIndex: 1, Notification: DSNOptions{Sign: SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Timestamp: testTime}, Recipients: []DSNRecipient{{FinalRecipient: incoming.RcptTo[0], Action: "failed", Status: "5.0.0", Diagnostic: "550 配信失敗"}}}})
	if err != nil {
		t.Fatal(err)
	}
	got := VerifyDSN(upstream.Wire, upstream.Envelope, DSNVerifyOptions{Verification: v, LocalDomains: []string{"example.com"}})
	if got.Status != Pass || got.HeadersOnly || !bytes.Equal(got.Original, first) || got.Recipients[0].Diagnostic != "550 配信失敗" {
		t.Fatalf("upstream international original: %+v", got)
	}
}
