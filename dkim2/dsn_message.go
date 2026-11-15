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
	part, err = multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {"message/delivery-status"}, "Content-Transfer-Encoding": {"7bit"}})
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(machine); err != nil {
		return nil, err
	}
	contentType := "message/rfc822"
	if options.HeadersOnly {
		contentType = "text/rfc822-headers"
	}
	transfer := "7bit"
	for _, b := range content {
		if b >= 128 {
			transfer = "8bit"
		}
		if b == 0 {
			return nil, errors.New("dkim2: DSN original contains a NUL octet")
		}
	}
	part, err = multipartWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {contentType}, "Content-Transfer-Encoding": {transfer}})
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(content); err != nil {
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
	fmt.Fprintf(&wire, "From: Mail Delivery System <postmaster@%s>\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <dsn.%s@%s>\r\nSubject: Delivery Status Notification\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status;\r\n boundary=%q\r\nContent-Transfer-Encoding: %s\r\n\r\n", options.Sign.Domain, to, when.Format(time.RFC1123Z), hex.EncodeToString(nonce[:]), options.Sign.Domain, multipartWriter.Boundary(), transfer)
	wire.Write(body.Bytes())
	signing := options.Sign
	signing.Envelope = envelope
	signed, err := Sign(wire.Bytes(), signing)
	if err != nil {
		return nil, err
	}
	return &GeneratedDSN{Wire: signed, Envelope: Envelope{MailFrom: "<>", RcptTo: append([]string(nil), envelope.RcptTo...)}}, nil
}

func buildDeliveryStatus(reporting string, recipients []DSNRecipient) ([]byte, error) {
	if len(recipients) == 0 || len(recipients) > maxHeaderFields {
		return nil, errors.New("dkim2: DSN requires between 1 and 4096 recipient results")
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "Reporting-MTA: dns; %s\r\n", reporting)
	for _, result := range recipients {
		result.Action = strings.ToLower(result.Action)
		statusCode, err := dsnStatusCode(result.Status)
		if err != nil {
			return nil, err
		}
		result.Status = statusCode
		path, err := normalizePath(result.FinalRecipient)
		if err != nil || !validPath(path, false) || !validDSNActionStatus(result.Action, result.Status) || !safeDSNText(result.Diagnostic, 800) {
			return nil, errors.New("dkim2: invalid DSN recipient, action, status or diagnostic")
		}
		// RFC 3464 section 2.3.2 requires the exact recipient spelling,
		// including alphabetic case, from the transport envelope.
		addressType, address := dsnRecipientAddress(result.FinalRecipient)
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
	if err != nil || contentType != "multipart/report" || !strings.EqualFold(parameters["report-type"], "delivery-status") || parameters["boundary"] == "" {
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
		partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return nil, errors.New("dkim2: invalid DSN part content type")
		}
		encoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		var input io.Reader = part
		switch encoding {
		case "", "7bit", "8bit", "binary":
		case "base64":
			if index == 1 || index == 2 && partType == "message/rfc822" {
				return nil, errors.New("dkim2: encoded message DSN part is not permitted")
			}
			input = base64.NewDecoder(base64.StdEncoding.Strict(), part)
		case "quoted-printable":
			if index == 1 || index == 2 && partType == "message/rfc822" {
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
			if partType != "message/delivery-status" || encoding != "" && encoding != "7bit" {
				return nil, errors.New("dkim2: DSN second part must be 7-bit delivery-status")
			}
			result.reportingMTA, result.recipients, err = parseDeliveryStatus(data)
			if err != nil {
				return nil, err
			}
		case 2:
			if partType != "message/rfc822" && partType != "text/rfc822-headers" {
				return nil, errors.New("dkim2: DSN third part must contain original message or headers")
			}
			result.original = data
			result.headersOnly = partType == "text/rfc822-headers"
			if result.headersOnly && bytes.Contains(data, []byte("\r\n\r\n")) {
				return nil, errors.New("dkim2: DSN headers-only part contains a body separator")
			}
		}
	}
	if part, err := reader.NextRawPart(); err != io.EOF || part != nil {
		return nil, errors.New("dkim2: DSN requires exactly three MIME parts and a closing boundary")
	}
	return result, nil
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
		value = strings.TrimSpace(value)
	}
	if required && (!found || value == "") {
		return "", fmt.Errorf("dkim2: missing DSN %s field", name)
	}
	return value, nil
}

// DSN fields are deliberately parsed independently of net/textproto so its
// unbounded header reader is never applied to attacker-provided MIME bodies.
func parseDeliveryStatus(data []byte) (string, []DSNRecipient, error) {
	for i, b := range data {
		if b >= 127 || b < 32 && b != '\r' && b != '\n' && b != '\t' || b == '\r' && (i+1 >= len(data) || data[i+1] != '\n') || b == '\n' && (i == 0 || data[i-1] != '\r') {
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
		for _, field := range fields {
			name, _, _ := strings.Cut(field, ":")
			name = strings.ToLower(name)
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
			if err != nil || !ok || !strings.EqualFold(strings.TrimSpace(kind), "dns") || !validDomain(strings.TrimSpace(name)) {
				return "", nil, errors.New("dkim2: invalid Reporting-MTA field")
			}
			reporting = strings.TrimSpace(name)
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
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "rfc822":
		case "utf-8":
			value, err = decodeDSNUnitext(value)
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
		if err != nil {
			return "", nil, err
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
			if !ok || !strings.EqualFold(strings.TrimSpace(kind), "smtp") || !safeDSNText(strings.TrimSpace(text), 800) {
				return "", nil, errors.New("dkim2: invalid SMTP diagnostic")
			}
			diagnostic = strings.TrimSpace(text)
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
	return strings.TrimSpace(out.String()), nil
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
	var out strings.Builder
	for i := 0; i < len(encoded); i++ {
		if encoded[i] != '\\' {
			if encoded[i] < 33 || encoded[i] > 126 || encoded[i] == '+' || encoded[i] == '=' {
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
		n, err := strconv.ParseUint(encoded[i+3:i+3+end], 16, 32)
		if err != nil || n > utf8.MaxRune || n >= 0xD800 && n <= 0xDFFF {
			return "", errors.New("dkim2: invalid UTF-8 DSN code point")
		}
		out.WriteRune(rune(n))
		i += 3 + end
	}
	return out.String(), nil
}
