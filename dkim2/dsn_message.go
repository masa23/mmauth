package dkim2

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/language"
)

// DSNRecipient is one RFC 3464 per-recipient delivery result. FinalRecipient
// is the actual SMTP path, including angle brackets. Diagnostic is an optional
// SMTP diagnostic (without the "smtp;" prefix). Callers provide actual outcomes.
type DSNRecipient struct {
	FinalRecipient string
	Action         string
	Status         string
	Diagnostic     string
}

// DSNOptions configures a new signed delivery report. The signing envelope is
// derived from the authenticated original and must not be supplied in Sign.
// Recipients is required; status information is never invented by the library.
type DSNOptions struct {
	Sign         SignOptions
	Verify       VerifyOptions
	ReportingMTA string
	HumanText    string
	Recipients   []DSNRecipient
	HeadersOnly  bool
}

// GeneratedDSN contains the signed wire message and the SMTP envelope which
// must be used to deliver it. MailFrom is always the null path.
type GeneratedDSN struct {
	Wire     []byte
	Envelope Envelope
}

type parsedDSN struct {
	message      *Message
	original     []byte
	headersOnly  bool
	humanText    string
	recipients   []DSNRecipient
	reportingMTA string
}

const maxDSNTextBytes = 1 << 20

// CreateDSN creates a draft-09 section 16 report only after provisional
// authentication. It never sends mail. The caller must deliver Envelope
// exactly, and must not generate a report in response to a null MAIL FROM.
func CreateDSN(original []byte, received Envelope, options DSNOptions) (*GeneratedDSN, error) {
	result := VerifyProvisional(original, received, options.Verify)
	if result.Status != Pass || result.PendingNextDomain {
		return nil, fmt.Errorf("dkim2: DSN requires provisional authentication without pending nd=: %s: %v", result.Status, result.Err)
	}
	m, err := Parse(original)
	if err != nil {
		return nil, err
	}
	latest := m.Signatures[len(m.Signatures)-1]
	if latest.MailFrom == "<>" || latest.MailFrom == "" {
		return nil, errors.New("dkim2: must not send a DSN to a null MAIL FROM")
	}
	if !recipientMatchesSigner(latest.Recipients, options.Sign.Domain) {
		return nil, errors.New("dkim2: DSN signer is not covered by original RCPT TO")
	}
	actualRecipients := received.RcptTo
	received, err = normalizeEnvelope(received)
	if err != nil {
		return nil, err
	}
	statuses := append([]DSNRecipient(nil), options.Recipients...)
	for i, recipient := range statuses {
		path, err := normalizePath(recipient.FinalRecipient)
		if err != nil {
			return nil, err
		}
		found := false
		for j, actual := range received.RcptTo {
			if equalPath(path, actual) {
				// RFC 3464 requires the spelling received over SMTP, not
				// a normalized or differently cased lookup key from the caller.
				statuses[i].FinalRecipient = actualRecipients[j]
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("dkim2: DSN status recipient was not an actual RCPT TO")
		}
	}
	options.Recipients = statuses
	envelope := Envelope{MailFrom: "<>", RcptTo: []string{latest.MailFrom}}
	return buildDSN(original, envelope, options)
}

// buildDSN is also used for authenticated propagation. Its caller establishes
// the relationship between the original, report signer and return envelope.
func buildDSN(original []byte, envelope Envelope, options DSNOptions) (*GeneratedDSN, error) {
	if options.Sign.NextDomain != "" || options.Sign.Envelope.MailFrom != "" || len(options.Sign.Envelope.RcptTo) != 0 || len(options.Sign.BCCRecipients) != 0 || options.Sign.OutOfBandArrangement {
		return nil, errors.New("dkim2: DSN signing options must not supply an envelope, nd= or an out-of-band arrangement")
	}
	if envelope.MailFrom != "<>" || len(envelope.RcptTo) != 1 || !validPath(envelope.RcptTo[0], false) {
		return nil, errors.New("dkim2: invalid DSN return envelope")
	}
	if !validDomain(options.Sign.Domain) || !validDomain(options.Sign.Selector) {
		return nil, errors.New("dkim2: invalid DSN signing domain or selector")
	}
	m, err := Parse(original)
	if err != nil {
		return nil, err
	}
	content := original
	if options.HeadersOnly {
		var headers bytes.Buffer
		for _, field := range m.Headers {
			headers.WriteString(field)
		}
		content = headers.Bytes()
	}
	reporting := options.ReportingMTA
	if reporting == "" {
		reporting = options.Sign.Domain
	}
	if !validDomain(reporting) {
		return nil, errors.New("dkim2: Reporting-MTA must be a DNS domain")
	}
	machine, err := buildDeliveryStatus(reporting, options.Recipients)
	if err != nil {
		return nil, err
	}
	statusType, statusTransfer := "message/delivery-status", "7bit"
	if dsnHas8Bit(machine) {
		statusType, statusTransfer = "message/global-delivery-status", "base64"
	}
	human := options.HumanText
	if human == "" {
		human = "This is a delivery status notification.\r\n"
	}
	if len(human) > maxDSNTextBytes || !utf8.ValidString(human) || strings.ContainsRune(human, 0) {
		return nil, errors.New("dkim2: invalid or oversized DSN human text")
	}
	human = strings.ReplaceAll(human, "\r\n", "\n")
	if strings.ContainsRune(human, '\r') {
		return nil, errors.New("dkim2: bare CR in DSN human text")
	}
	human = strings.ReplaceAll(human, "\n", "\r\n")
	var body bytes.Buffer
	multipartWriter := multipart.NewWriter(&body)
	part, err := multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(part)
	if _, err := io.WriteString(qp, human); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	part, err = multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {statusType}, "Content-Transfer-Encoding": {statusTransfer}})
	if err != nil {
		return nil, err
	}
	if err := writeDSNPart(part, machine, statusTransfer); err != nil {
		return nil, err
	}
	contentType := "message/rfc822"
	if options.HeadersOnly {
		contentType = "text/rfc822-headers"
	}
	transfer := "7bit"
	for _, b := range content {
		if b >= 128 {
			// An 8-bit octet may belong to an internationalized MIME child
			// header even when the outer headers are ASCII. The global
			// container safely covers that case without recursive MIME parsing.
			contentType, transfer = "message/global", "base64"
			if options.HeadersOnly {
				contentType = "message/global-headers"
			}
		}
		if b == 0 {
			return nil, errors.New("dkim2: DSN original contains a NUL octet")
		}
	}
	if transfer == "base64" {
		for _, header := range m.Headers {
			if !utf8.ValidString(header) {
				return nil, errors.New("dkim2: global original headers are not UTF-8")
			}
		}
	}
	part, err = multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {contentType}, "Content-Transfer-Encoding": {transfer}})
	if err != nil {
		return nil, err
	}
	if err := writeDSNPart(part, content, transfer); err != nil {
		return nil, err
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	when := options.Sign.Timestamp
	if when.IsZero() {
		when = time.Now()
	}
	to := envelope.RcptTo[0]
	if strings.ContainsAny(to, "\r\n\x00") || len(to) > 900 {
		return nil, errors.New("dkim2: invalid DSN To field")
	}
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "From: Mail Delivery System <postmaster@%s>\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <dsn.%s@%s>\r\nSubject: Delivery Status Notification\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=%s;\r\n boundary=%q\r\nContent-Transfer-Encoding: 7bit\r\n\r\n", options.Sign.Domain, to, when.Format(time.RFC1123Z), hex.EncodeToString(nonce[:]), options.Sign.Domain, strings.TrimPrefix(statusType, "message/"), multipartWriter.Boundary())
	wire.Write(body.Bytes())
	signing := options.Sign
	signing.Envelope = envelope
	signed, err := Sign(wire.Bytes(), signing)
	if err != nil {
		return nil, err
	}
	return &GeneratedDSN{Wire: signed, Envelope: Envelope{MailFrom: "<>", RcptTo: append([]string(nil), envelope.RcptTo...)}}, nil
}

// dsnHas8Bit conservatively identifies data that requires an internationalized
// MIME container, including UTF-8 headers in nested MIME entities.
func dsnHas8Bit(data []byte) bool {
	for _, b := range data {
		if b >= 128 {
			return true
		}
	}
	return false
}

// writeDSNPart preserves the content's exact octets while making international
// bodies safe for a 7-bit return transport, using RFC 2045's 76-column folding.
func writeDSNPart(out io.Writer, data []byte, transfer string) error {
	if transfer != "base64" {
		_, err := out.Write(data)
		return err
	}
	var encoded [76]byte
	for len(data) > 0 {
		n := len(data)
		if n > 57 {
			n = 57
		}
		size := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(encoded[:size], data[:n])
		if _, err := out.Write(encoded[:size]); err != nil {
			return err
		}
		if _, err := io.WriteString(out, "\r\n"); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func buildDeliveryStatus(reporting string, recipients []DSNRecipient) ([]byte, error) {
	if len(recipients) == 0 || len(recipients) > maxHeaderFields {
		return nil, errors.New("dkim2: DSN requires between 1 and 4096 recipient results")
	}
	var out bytes.Buffer
	global := false
	for _, recipient := range recipients {
		global = global || dsnHas8Bit([]byte(recipient.Diagnostic))
	}
	fmt.Fprintf(&out, "Reporting-MTA: dns; %s\r\n", reporting)
	for _, result := range recipients {
		if !safeDSNText(result.Action, len(result.Action)) {
			return nil, errors.New("dkim2: DSN action must be an ASCII token")
		}
		result.Action = strings.ToLower(result.Action)
		statusCode, err := dsnStatusCode(result.Status)
		if err != nil {
			return nil, err
		}
		result.Status = statusCode
		path, err := normalizePath(result.FinalRecipient)
		if err != nil || !validPath(path, false) || !validDSNActionStatus(result.Action, result.Status) || !safeDSNUTF8Text(result.Diagnostic, 800) {
			return nil, errors.New("dkim2: invalid DSN recipient, action, status or diagnostic")
		}
		// RFC 3464 section 2.3.2 requires the exact recipient spelling,
		// including alphabetic case, from the transport envelope.
		addressType, address := dsnRecipientAddress(result.FinalRecipient)
		native := result.FinalRecipient[1 : len(result.FinalRecipient)-1]
		if global && addressType == "utf-8" && !strings.Contains(native, `\x{`) {
			// RFC 6533 recommends the native address form in global status.
			// Keep unitext when a quoted SMTP pair could be confused with
			// the transitional escape form and change the recipient's value.
			address = native
		}
		if len(address)+len(addressType)+20 > 998 {
			return nil, errors.New("dkim2: DSN recipient field exceeds line limit")
		}
		fmt.Fprintf(&out, "\r\nFinal-Recipient: %s; %s\r\nAction: %s\r\nStatus: %s\r\n", addressType, address, result.Action, result.Status)
		if result.Diagnostic != "" {
			fmt.Fprintf(&out, "Diagnostic-Code: smtp; %s\r\n", result.Diagnostic)
		}
		if out.Len() > maxDSNTextBytes {
			return nil, errors.New("dkim2: DSN delivery status exceeds 1 MiB")
		}
	}
	return out.Bytes(), nil
}

// safeDSNUTF8Text permits printable UTF-8 without accepting header delimiters,
// invalid encodings, or control octets in a caller-supplied diagnostic.
func safeDSNUTF8Text(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func safeDSNText(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, c := range value {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func validDSNActionStatus(action, status string) bool {
	if !safeDSNText(action, len(action)) {
		return false
	}
	action = strings.ToLower(action)
	parts := strings.Split(status, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || !strings.ContainsAny(parts[0], "245") {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	switch action {
	case "failed", "delayed", "delivered", "relayed", "expanded":
		// RFC 3464 section 2.3.3 explicitly makes Action independent of
		// Status: failed + 4.x.x is valid after retries are abandoned.
		return true
	}
	return false
}

// RFC 3464 permits a trailing RFC 822 comment after a status code. Keep only
// the numeric code, accepting bounded nested comments and quoted pairs.
func dsnStatusCode(value string) (string, error) {
	if len(value) > 998 {
		return "", errors.New("dkim2: DSN status exceeds line limit")
	}
	return stripDSNComments(value)
}

// RFC 6533 section 3 permits a 7-bit-safe UTF-8 address type in the existing
// message/delivery-status format. Encode all non-QCHAR runes with unitext.
func dsnRecipientAddress(path string) (string, string) {
	address := path[1 : len(path)-1]
	for _, c := range address {
		if c >= 128 {
			var out strings.Builder
			for _, r := range address {
				if r < 33 || r > 126 || r == '\\' || r == '+' || r == '=' {
					fmt.Fprintf(&out, "\\x{%X}", r)
				} else {
					out.WriteRune(r)
				}
			}
			return "utf-8", out.String()
		}
	}
	return "rfc822", address
}

func parseDSN(wire []byte) (*parsedDSN, error) {
	m, err := Parse(wire)
	if err != nil {
		return nil, err
	}
	value, err := dsnSingleHeader(m.Headers, "Content-Type", true)
	if err != nil {
		return nil, err
	}
	contentType, parameters, err := mime.ParseMediaType(value)
	if !safeDSNText(parameters["report-type"], len(parameters["report-type"])) {
		return nil, errors.New("dkim2: DSN report-type must be an ASCII token")
	}
	reportType := strings.ToLower(parameters["report-type"])
	if err != nil || contentType != "multipart/report" || reportType != "delivery-status" && reportType != "global-delivery-status" || parameters["boundary"] == "" {
		return nil, errors.New("dkim2: expected multipart/report with delivery-status report-type")
	}
	if err := multipart.NewWriter(io.Discard).SetBoundary(parameters["boundary"]); err != nil {
		return nil, errors.New("dkim2: invalid DSN MIME boundary")
	}
	if version, err := dsnSingleHeader(m.Headers, "MIME-Version", false); err != nil || version != "" && version != "1.0" {
		return nil, errors.New("dkim2: invalid DSN MIME-Version")
	}
	if encoding, err := dsnSingleHeader(m.Headers, "Content-Transfer-Encoding", false); err != nil || !rawMIMEEncoding(encoding) {
		return nil, errors.New("dkim2: unsupported DSN multipart transfer encoding")
	}
	// Bound each raw MIME header block before multipart's header reader can
	// allocate maps or concatenate arbitrary numbers of continuation lines.
	if err := preflightDSNPartHeaders(m.Body, parameters["boundary"]); err != nil {
		return nil, err
	}
	reader := multipart.NewReader(bytes.NewReader(m.Body), parameters["boundary"])
	result := &parsedDSN{message: m}
	for index := 0; index < 3; index++ {
		part, err := reader.NextRawPart()
		if err != nil {
			return nil, fmt.Errorf("dkim2: DSN requires exactly three complete MIME parts: %w", err)
		}
		if len(part.Header.Values("Content-Type")) != 1 || len(part.Header.Values("Content-Transfer-Encoding")) > 1 {
			return nil, errors.New("dkim2: ambiguous DSN part headers")
		}
		headerBytes, headerCount := 0, 0
		for name, values := range part.Header {
			for _, value := range values {
				headerCount++
				size := len(name) + len(value) + 4
				headerBytes += size
				if size > maxHeaderFieldBytes || headerCount > maxHeaderFields || headerBytes > maxHeaderBytes {
					return nil, errors.New("dkim2: DSN MIME part headers exceed limits")
				}
			}
		}
		partType, partParameters, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return nil, errors.New("dkim2: invalid DSN part content type")
		}
		global := partType == "message/global" || partType == "message/global-headers" || partType == "message/global-delivery-status"
		if global && len(partParameters) != 0 {
			return nil, errors.New("dkim2: global DSN part must not have content-type parameters")
		}
		encoding := strings.Trim(part.Header.Get("Content-Transfer-Encoding"), " \t")
		if !safeDSNText(encoding, len(encoding)) {
			return nil, errors.New("dkim2: DSN transfer encoding must be an ASCII token")
		}
		encoding = strings.ToLower(encoding)
		var input io.Reader = part
		switch encoding {
		case "", "7bit", "8bit", "binary":
		case "base64":
			if index == 1 && !global || index == 2 && partType == "message/rfc822" {
				return nil, errors.New("dkim2: encoded message DSN part is not permitted")
			}
			input = base64.NewDecoder(base64.StdEncoding.Strict(), dsnMIMEBase64Reader{part})
		case "quoted-printable":
			if index == 1 && !global || index == 2 && partType == "message/rfc822" {
				return nil, errors.New("dkim2: encoded message DSN part is not permitted")
			}
			input = quotedprintable.NewReader(part)
		default:
			return nil, errors.New("dkim2: unsupported DSN part transfer encoding")
		}
		limit := maxMessageBytes
		if index < 2 {
			limit = maxDSNTextBytes
		}
		data, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
		if err != nil || len(data) > limit {
			return nil, errors.New("dkim2: invalid or oversized DSN part")
		}
		if global && (encoding == "" || encoding == "7bit") && dsnHas8Bit(data) {
			return nil, errors.New("dkim2: global DSN part has 8-bit data under a 7-bit transfer encoding")
		}
		if err := part.Close(); err != nil {
			return nil, err
		}
		switch index {
		case 0:
			if !strings.HasPrefix(partType, "text/") && partType != "multipart/alternative" {
				return nil, errors.New("dkim2: DSN human-readable part must be text")
			}
			// Alternative human presentations are opaque, size-bounded data.
			// Authentication covers their exact bytes; this library neither
			// renders them nor copies them into a propagated report.
			result.humanText = string(data)
		case 1:
			if partType != "message/"+reportType || partType == "message/delivery-status" && encoding != "" && encoding != "7bit" {
				return nil, errors.New("dkim2: DSN second part must be 7-bit delivery-status")
			}
			if global && (encoding == "" || encoding == "7bit" || encoding == "binary") {
				return nil, errors.New("dkim2: global delivery status requires 8bit or an encoded transfer form")
			}
			result.reportingMTA, result.recipients, err = parseDeliveryStatusMode(data, global)
			if err != nil {
				return nil, err
			}
		case 2:
			if partType != "message/rfc822" && partType != "text/rfc822-headers" && partType != "message/global" && partType != "message/global-headers" {
				return nil, errors.New("dkim2: DSN third part must contain original message or headers")
			}
			result.original = data
			result.headersOnly = partType == "text/rfc822-headers" || partType == "message/global-headers"
			if result.headersOnly && bytes.Contains(data, []byte("\r\n\r\n")) {
				return nil, errors.New("dkim2: DSN headers-only part contains a body separator")
			}
			embedded, err := Parse(data)
			if err != nil {
				return nil, fmt.Errorf("dkim2: invalid DSN original: %w", err)
			}
			for _, header := range embedded.Headers {
				if global && !utf8.ValidString(header) {
					return nil, errors.New("dkim2: global original headers are not UTF-8")
				}
				if !global && dsnHas8Bit([]byte(header)) {
					return nil, errors.New("dkim2: traditional DSN original headers are not ASCII")
				}
			}
		}
	}
	if part, err := reader.NextRawPart(); err != io.EOF || part != nil {
		return nil, errors.New("dkim2: DSN requires exactly three MIME parts and a closing boundary")
	}
	return result, nil
}

// dsnMIMEBase64Reader ignores non-alphabet octets as required by RFC 2045
// section 6.8. This MIME-only filtering never changes signed DKIM2 tag decoding.
type dsnMIMEBase64Reader struct{ io.Reader }

func (r dsnMIMEBase64Reader) Read(p []byte) (int, error) {
	for {
		n, err := r.Reader.Read(p)
		count := 0
		for _, c := range p[:n] {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
				p[count] = c
				count++
			}
		}
		if count != 0 || err != nil || n == 0 {
			return count, err
		}
	}
}

func preflightDSNPartHeaders(body []byte, boundary string) error {
	delimiter := []byte("--" + boundary)
	headerBytes, headerCount, fieldBytes := 0, 0, 0
	inHeaders, parts := false, 0
	for len(body) > 0 {
		end := bytes.Index(body, []byte("\r\n"))
		var line []byte
		if end < 0 {
			line, body = body, nil
		} else {
			line, body = body[:end], body[end+2:]
		}
		kind := dsnBoundaryLine(line, delimiter)
		if kind != 0 {
			if inHeaders {
				return errors.New("dkim2: DSN MIME part headers lack a separator")
			}
			if kind == 2 {
				return nil // MIME epilogue is opaque; multipart agrees.
			}
			parts++
			if parts > 3 {
				return errors.New("dkim2: DSN contains excess MIME parts")
			}
			inHeaders = true
			headerBytes, headerCount, fieldBytes = 0, 0, 0
			continue
		}
		if !inHeaders {
			continue
		}
		if len(line) == 0 {
			inHeaders = false
			continue
		}
		headerBytes += len(line) + 2
		if line[0] == ' ' || line[0] == '\t' {
			if headerCount == 0 {
				return errors.New("dkim2: orphan MIME header continuation")
			}
			fieldBytes += len(line) + 2
		} else {
			headerCount++
			fieldBytes = len(line) + 2
			if headerBytes > maxHeaderBytes || headerCount > maxHeaderFields || fieldBytes > maxHeaderFieldBytes {
				return errors.New("dkim2: DSN MIME part headers exceed limits")
			}
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 || !validFieldName(string(line[:colon])) {
				return errors.New("dkim2: invalid DSN MIME header name")
			}
		}
		if headerBytes > maxHeaderBytes || headerCount > maxHeaderFields || fieldBytes > maxHeaderFieldBytes {
			return errors.New("dkim2: DSN MIME part headers exceed limits")
		}
	}
	return errors.New("dkim2: DSN lacks a closing MIME boundary")
}

// multipart permits optional SP/HTAB after a delimiter, and recognizes a final
// delimiter even without a trailing CRLF. Other prefix matches are body data.
func dsnBoundaryLine(line, delimiter []byte) int {
	if !bytes.HasPrefix(line, delimiter) {
		return 0
	}
	rest, kind := line[len(delimiter):], 1
	if bytes.HasPrefix(rest, []byte("--")) {
		rest, kind = rest[2:], 2
	}
	for _, c := range rest {
		if c != ' ' && c != '\t' {
			return 0
		}
	}
	return kind
}

func rawMIMEEncoding(value string) bool {
	if !safeDSNText(value, len(value)) {
		return false
	}
	switch strings.ToLower(value) {
	case "", "7bit", "8bit", "binary":
		return true
	}
	return false
}

func dsnSingleHeader(fields []string, name string, required bool) (string, error) {
	var found bool
	var value string
	for _, raw := range fields {
		n, _, _ := strings.Cut(raw, ":")
		if !strings.EqualFold(n, name) {
			continue
		}
		if found {
			return "", fmt.Errorf("dkim2: duplicate DSN %s field", name)
		}
		found = true
		unfolded, err := unfold(raw)
		if err != nil {
			return "", err
		}
		_, value, _ = strings.Cut(unfolded, ":")
		value = strings.Trim(value, " \t")
	}
	if required && (!found || value == "") {
		return "", fmt.Errorf("dkim2: missing DSN %s field", name)
	}
	return value, nil
}

// DSN fields are deliberately parsed independently of net/textproto so its
// unbounded header reader is never applied to attacker-provided MIME bodies.
func parseDeliveryStatus(data []byte) (string, []DSNRecipient, error) {
	return parseDeliveryStatusMode(data, false)
}

// parseDeliveryStatusMode interprets UTF-8 only for the RFC 6533 global type;
// the traditional type remains bounded 7-bit CRLF data.
func parseDeliveryStatusMode(data []byte, global bool) (string, []DSNRecipient, error) {
	if global && !utf8.Valid(data) {
		return "", nil, errors.New("dkim2: global delivery status is not UTF-8")
	}
	for i, b := range data {
		if b == 127 || b >= 128 && !global || b < 32 && b != '\r' && b != '\n' && b != '\t' || b == '\r' && (i+1 >= len(data) || data[i+1] != '\n') || b == '\n' && (i == 0 || data[i-1] != '\r') {
			return "", nil, errors.New("dkim2: delivery status is not 7-bit CRLF data")
		}
	}
	data = bytes.TrimSuffix(data, []byte("\r\n"))
	blocks := bytes.Split(data, []byte("\r\n\r\n"))
	if len(blocks) < 2 || len(blocks) > maxHeaderFields+1 {
		return "", nil, errors.New("dkim2: delivery status requires message and recipient blocks")
	}
	var reporting string
	var recipients []DSNRecipient
	for index, block := range blocks {
		fields, err := dsnStatusFields(block)
		if err != nil {
			return "", nil, fmt.Errorf("dkim2: invalid delivery status fields: %w", err)
		}
		seen := make(map[string]bool)
		languages := make(map[string]bool)
		for _, field := range fields {
			name, _, _ := strings.Cut(field, ":")
			name = strings.ToLower(name)
			if name == "localized-diagnostic" && global {
				if index == 0 {
					return "", nil, errors.New("dkim2: localized diagnostic occurs in the message block")
				}
				unfolded, err := unfold(field)
				if err != nil {
					return "", nil, err
				}
				_, value, _ := strings.Cut(unfolded, ":")
				tag, text, ok := strings.Cut(value, ";")
				tag = strings.Trim(tag, " \t")
				if !ok || !seen["diagnostic-code"] || !safeDSNUTF8Text(strings.Trim(text, " \t\r\n"), maxHeaderFieldBytes) {
					return "", nil, errors.New("dkim2: invalid localized diagnostic")
				}
				if _, err := language.Parse(tag); err != nil || languages[strings.ToLower(tag)] {
					return "", nil, errors.New("dkim2: invalid or duplicate localized diagnostic language")
				}
				languages[strings.ToLower(tag)] = true
				continue
			}
			if seen[name] {
				return "", nil, errors.New("dkim2: duplicate delivery status field")
			}
			seen[name] = true
			if index == 0 && (name == "final-recipient" || name == "action" || name == "status" || name == "diagnostic-code") || index != 0 && name == "reporting-mta" {
				return "", nil, errors.New("dkim2: DSN field occurs in the wrong status block")
			}
		}
		if index == 0 {
			value, err := dsnStatusValue(fields, "Reporting-MTA", true)
			kind, name, ok := strings.Cut(value, ";")
			kind = strings.Trim(kind, " \t")
			if err != nil || !ok || !safeDSNText(kind, len(kind)) || !strings.EqualFold(kind, "dns") || !validDomain(strings.Trim(name, " \t")) {
				return "", nil, errors.New("dkim2: invalid Reporting-MTA field")
			}
			reporting = strings.Trim(name, " \t")
			continue
		}
		address, err := dsnStatusValue(fields, "Final-Recipient", true)
		if err != nil {
			return "", nil, err
		}
		kind, value, ok := strings.Cut(address, ";")
		if !ok {
			return "", nil, errors.New("dkim2: invalid Final-Recipient field")
		}
		value = strings.Trim(value, " \t")
		kind = strings.Trim(kind, " \t")
		if !safeDSNText(kind, len(kind)) {
			return "", nil, errors.New("dkim2: DSN address type must be an ASCII token")
		}
		switch strings.ToLower(kind) {
		case "rfc822":
			if dsnHas8Bit([]byte(value)) {
				return "", nil, errors.New("dkim2: rfc822 DSN recipient is not ASCII")
			}
		case "utf-8":
			value, err = decodeDSNRecipient(value, global)
			if err != nil {
				return "", nil, err
			}
		default:
			return "", nil, errors.New("dkim2: unsupported DSN recipient address type")
		}
		path := "<" + value + ">"
		normalized, err := normalizePath(path)
		if err != nil || !validPath(normalized, false) {
			return "", nil, errors.New("dkim2: invalid DSN recipient mailbox")
		}
		action, err := dsnStatusValue(fields, "Action", true)
		if err != nil || !safeDSNText(action, len(action)) {
			return "", nil, errors.New("dkim2: invalid DSN action token")
		}
		action = strings.ToLower(action)
		status, err := dsnSingleHeader(fields, "Status", true)
		if err == nil {
			status, err = dsnStatusCode(status)
		}
		if err != nil || !validDSNActionStatus(action, status) {
			return "", nil, errors.New("dkim2: invalid DSN action/status")
		}
		diagnostic, err := dsnSingleHeader(fields, "Diagnostic-Code", false)
		if err != nil {
			return "", nil, err
		}
		if diagnostic != "" {
			kind, text, ok := strings.Cut(diagnostic, ";")
			kind = strings.Trim(kind, " \t")
			text = strings.Trim(text, " \t")
			if !ok || !safeDSNText(kind, len(kind)) || !strings.EqualFold(kind, "smtp") || !safeDSNUTF8Text(text, 800) || !global && !safeDSNText(text, 800) {
				return "", nil, errors.New("dkim2: invalid SMTP diagnostic")
			}
			diagnostic = text
		}
		recipients = append(recipients, DSNRecipient{FinalRecipient: path, Action: action, Status: status, Diagnostic: diagnostic})
	}
	return reporting, recipients, nil
}

func dsnStatusValue(fields []string, name string, required bool) (string, error) {
	value, err := dsnSingleHeader(fields, name, required)
	if err != nil {
		return "", err
	}
	return stripDSNComments(value)
}

// Comments represent CFWS, not removable characters within lexical tokens.
// Preserve quoted mailbox text, and replace each comment with a space so a
// comment cannot splice two invalid token halves into an accepted value.
func stripDSNComments(value string) (string, error) {
	var out strings.Builder
	depth, quoted := 0, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if depth > 0 {
			switch c {
			case '\\':
				i++
				if i >= len(value) {
					return "", errors.New("dkim2: truncated DSN comment quoted pair")
				}
			case '(':
				depth++
				if depth > 32 {
					return "", errors.New("dkim2: DSN comment nesting exceeds limit")
				}
			case ')':
				depth--
			}
			continue
		}
		if quoted && c == '\\' {
			out.WriteByte(c)
			i++
			if i >= len(value) {
				return "", errors.New("dkim2: truncated DSN quoted mailbox")
			}
			out.WriteByte(value[i])
			continue
		}
		if c == '"' {
			quoted = !quoted
		}
		if !quoted && c == '(' {
			depth = 1
			out.WriteByte(' ')
			continue
		}
		if !quoted && c == ')' {
			return "", errors.New("dkim2: unmatched DSN comment terminator")
		}
		out.WriteByte(c)
	}
	if depth != 0 || quoted {
		return "", errors.New("dkim2: unclosed DSN comment or quote")
	}
	return strings.Trim(out.String(), " \t"), nil
}

func dsnStatusFields(block []byte) ([]string, error) {
	if len(block) == 0 || len(block) > maxHeaderBytes {
		return nil, errors.New("dkim2: empty or oversized DSN status block")
	}
	lines := bytes.Split(block, []byte("\r\n"))
	var fields []string
	var field strings.Builder
	flush := func() {
		if field.Len() != 0 {
			fields = append(fields, field.String())
			field = strings.Builder{}
		}
	}
	for _, line := range lines {
		if len(line) == 0 {
			return nil, errors.New("dkim2: empty line in DSN status block")
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			name, _, ok := strings.Cut(string(line), ":")
			if !ok || !validFieldName(name) || len(fields) >= maxHeaderFields {
				return nil, errors.New("dkim2: invalid DSN status field")
			}
		} else if field.Len() == 0 {
			return nil, errors.New("dkim2: orphan DSN status continuation")
		}
		if field.Len()+len(line)+2 > maxHeaderFieldBytes {
			return nil, errors.New("dkim2: DSN status field exceeds limits")
		}
		field.Write(line)
		field.WriteString("\r\n")
	}
	flush()
	return fields, nil
}

func decodeDSNUnitext(encoded string) (string, error) {
	return decodeDSNUnitextMode(encoded, false)
}

// decodeDSNRecipient accepts the global native address form as well as the
// transitional unitext form. Only a valid SMTP mailbox can survive either path.
func decodeDSNRecipient(value string, global bool) (string, error) {
	decoded, err := decodeDSNUnitextMode(value, global)
	if err == nil {
		if normalized, pathErr := normalizePath("<" + decoded + ">"); pathErr == nil && validPath(normalized, false) {
			return decoded, nil
		}
	}
	if global {
		if normalized, pathErr := normalizePath("<" + value + ">"); pathErr == nil && validPath(normalized, false) {
			return value, nil
		}
	}
	return "", errors.New("dkim2: invalid UTF-8 DSN recipient")
}

// decodeDSNUnitextMode applies QUCHAR only in a global body, preserves Unicode
// octets exactly, and accepts only the code points permitted by HEXPOINT.
func decodeDSNUnitextMode(encoded string, global bool) (string, error) {
	if !utf8.ValidString(encoded) {
		return "", errors.New("dkim2: invalid UTF-8 DSN encoded address")
	}
	var out strings.Builder
	for i := 0; i < len(encoded); i++ {
		if encoded[i] != '\\' {
			if encoded[i] < 33 || encoded[i] == 127 || encoded[i] >= 128 && !global || encoded[i] == '+' || encoded[i] == '=' {
				return "", errors.New("dkim2: invalid UTF-8 DSN encoded address")
			}
			out.WriteByte(encoded[i])
			continue
		}
		if !strings.HasPrefix(encoded[i:], "\\x{") {
			return "", errors.New("dkim2: invalid UTF-8 DSN escape")
		}
		end := strings.IndexByte(encoded[i+3:], '}')
		if end < 0 || end < 2 || end > 6 {
			return "", errors.New("dkim2: invalid UTF-8 DSN escape length")
		}
		hexPoint := encoded[i+3 : i+3+end]
		n, err := strconv.ParseUint(hexPoint, 16, 32)
		if err != nil || n == 0 || n > utf8.MaxRune || n >= 0xD800 && n <= 0xDFFF || end > 2 && hexPoint[0] == '0' || n < 128 && !(n <= 0x20 || n == 0x2B || n == 0x3D || n == 0x5C || n == 0x7F) {
			return "", errors.New("dkim2: invalid UTF-8 DSN code point")
		}
		out.WriteRune(rune(n))
		i += 3 + end
	}
	return out.String(), nil
}
