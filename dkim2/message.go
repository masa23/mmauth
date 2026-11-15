package dkim2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// Envelope contains the SMTP paths, including angle brackets and without
// SMTP parameters. A verifier must supply the paths of the actual delivery.
type Envelope struct {
	MailFrom string
	RcptTo   []string
}

// HashSet holds one Message-Instance hash pair.
type HashSet struct {
	Algorithm string
	Header    string
	Body      string
}

// Instance describes a Message-Instance field.
type Instance struct {
	Number     int
	Hashes     []HashSet
	HashGroups [][]HashSet // comma is AND; pipe is OR
	Recipe     string      // base64-encoded JSON, if present
	Raw        string
}

// SignatureValue is one selector, algorithm and signature tuple.
type SignatureValue struct {
	Selector  string
	Algorithm string
	Value     string
}

// Signature describes a DKIM2-Signature field.
type Signature struct {
	Index       int
	Instance    int
	Timestamp   int64
	MailFrom    string
	Recipients  []string
	NextDomain  string
	Domain      string
	Values      []SignatureValue
	ValueGroups [][]SignatureValue // comma is AND; pipe is OR
	Nonce       string
	Flags       []string
	Raw         string
}

// Message contains the original wire header fields and body. Fields are
// preserved so verification can hash the exact bytes that were received.
type Message struct {
	Headers    []string
	Body       []byte
	Instances  []Instance
	Signatures []Signature
	separator  bool
}

// Parse splits an RFC 5322 message and parses its DKIM2 fields.
func Parse(wire []byte) (*Message, error) {
	m := &Message{}
	sep := bytes.Index(wire, []byte("\r\n\r\n"))
	for i, c := range wire {
		if c == '\r' && (i+1 >= len(wire) || wire[i+1] != '\n') ||
			c == '\n' && (i == 0 || wire[i-1] != '\r') {
			return nil, errors.New("dkim2: non-CRLF line ending")
		}
	}
	var block []byte
	if sep >= 0 {
		block, m.Body, m.separator = wire[:sep+2], wire[sep+4:], true
	} else {
		block = wire // RFC 5322 permits a message with only header fields.
	}
	if len(block) == 0 {
		return nil, errors.New("dkim2: message has no header fields")
	}
	if !bytes.HasSuffix(block, []byte("\r\n")) {
		return nil, errors.New("dkim2: unterminated header field")
	}
	for len(block) > 0 {
		end := bytes.Index(block, []byte("\r\n"))
		if end < 0 {
			return nil, errors.New("dkim2: malformed header field")
		}
		field := append([]byte(nil), block[:end+2]...)
		block = block[end+2:]
		for len(block) > 0 && (block[0] == ' ' || block[0] == '\t') {
			end = bytes.Index(block, []byte("\r\n"))
			if end < 0 {
				return nil, errors.New("dkim2: unterminated folded header field")
			}
			field = append(field, block[:end+2]...)
			block = block[end+2:]
		}
		name, _, ok := strings.Cut(string(field), ":")
		if !ok || !validFieldName(name) {
			return nil, errors.New("dkim2: invalid header field name")
		}
		m.Headers = append(m.Headers, string(field))
		switch strings.ToLower(name) {
		case "message-instance":
			inst, err := parseInstance(string(field))
			if err != nil {
				return nil, err
			}
			m.Instances = append(m.Instances, inst)
		case "dkim2-signature":
			sig, err := parseSignature(string(field))
			if err != nil {
				return nil, err
			}
			m.Signatures = append(m.Signatures, sig)
		}
	}
	sort.Slice(m.Instances, func(i, j int) bool { return m.Instances[i].Number < m.Instances[j].Number })
	sort.Slice(m.Signatures, func(i, j int) bool { return m.Signatures[i].Index < m.Signatures[j].Index })
	return m, nil
}

func validFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 || s[i] == ':' {
			return false
		}
	}
	return true
}

func unfold(s string) (string, error) {
	if !strings.HasSuffix(s, "\r\n") {
		return "", errors.New("missing CRLF")
	}
	s = strings.TrimSuffix(s, "\r\n")
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			if i+2 >= len(s) || s[i+1] != '\n' || (s[i+2] != ' ' && s[i+2] != '\t') {
				return "", errors.New("invalid header folding")
			}
			s = s[:i] + s[i+2:]
		} else if s[i] == '\n' {
			return "", errors.New("bare newline in header")
		}
	}
	return s, nil
}

func tags(raw string) (map[string]string, error) {
	unfolded, err := unfold(raw)
	if err != nil {
		return nil, err
	}
	_, value, ok := strings.Cut(unfolded, ":")
	if !ok {
		return nil, errors.New("missing header colon")
	}
	out := make(map[string]string)
	parts := strings.Split(value, ";")
	for index, part := range parts {
		part = strings.Trim(part, " \t")
		if part == "" {
			if index != len(parts)-1 {
				return nil, errors.New("empty tag between semicolons")
			}
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.Trim(k, " \t")
		if !ok || k == "" || !validTag(k) {
			return nil, fmt.Errorf("invalid tag %q", k)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate tag %q", k)
		}
		out[k] = strings.Trim(v, " \t")
	}
	return out, nil
}

func validTag(s string) bool {
	if len(s) == 0 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func validTextString(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func decimal(v string) (int64, error) {
	if v == "" {
		return 0, errors.New("empty number")
	}
	for i := range v {
		if v[i] < '0' || v[i] > '9' {
			return 0, errors.New("non-decimal number")
		}
	}
	return strconv.ParseInt(v, 10, 64)
}

func positive(v string) (int, error) {
	n, err := decimal(v)
	if err != nil || n <= 0 || n > int64(^uint(0)>>1) {
		return 0, errors.New("invalid sequence number")
	}
	return int(n), nil
}

func stripWSP(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}

func b64(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(stripWSP(s)) }

func parseInstance(raw string) (Instance, error) {
	t, err := tags(raw)
	if err != nil {
		return Instance{}, fmt.Errorf("dkim2: Message-Instance: %w", err)
	}
	n, err := positive(t["m"])
	if err != nil {
		return Instance{}, fmt.Errorf("dkim2: Message-Instance m=: %w", err)
	}
	if t["h"] == "" {
		return Instance{}, errors.New("dkim2: Message-Instance h= is missing")
	}
	inst := Instance{Number: n, Raw: raw, Recipe: t["r"]}
	if _, ok := t["r"]; ok {
		if t["r"] == "" {
			return Instance{}, errors.New("dkim2: empty r= Recipe")
		}
		if _, err := b64(t["r"]); err != nil {
			return Instance{}, fmt.Errorf("dkim2: invalid Recipe base64: %w", err)
		}
	}
	seen := make(map[string]bool)
	for _, group := range strings.Split(t["h"], "|") {
		var sets []HashSet
		for _, entry := range strings.Split(group, ",") {
			parts := strings.Split(entry, ":")
			if len(parts) != 3 {
				return Instance{}, errors.New("dkim2: invalid h= hash set")
			}
			algo := strings.Trim(parts[0], " \t")
			if !validTextString(algo) || seen[algo] {
				return Instance{}, errors.New("dkim2: duplicate or empty hash algorithm")
			}
			seen[algo] = true
			headerHash, bodyHash := stripWSP(parts[1]), stripWSP(parts[2])
			if headerHash == "" || bodyHash == "" {
				return Instance{}, errors.New("dkim2: empty h= hash value")
			}
			decodedHeader, err := b64(headerHash)
			if err != nil {
				return Instance{}, fmt.Errorf("dkim2: invalid header hash: %w", err)
			}
			decodedBody, err := b64(bodyHash)
			if err != nil {
				return Instance{}, fmt.Errorf("dkim2: invalid body hash: %w", err)
			}
			if (algo == "sha256" && (len(decodedHeader) != 32 || len(decodedBody) != 32)) || (algo == "sha512" && (len(decodedHeader) != 64 || len(decodedBody) != 64)) {
				return Instance{}, errors.New("dkim2: incorrect hash length")
			}
			set := HashSet{algo, headerHash, bodyHash}
			inst.Hashes = append(inst.Hashes, set)
			sets = append(sets, set)
		}
		inst.HashGroups = append(inst.HashGroups, sets)
	}
	return inst, nil
}

func parseSignature(raw string) (Signature, error) {
	t, err := tags(raw)
	if err != nil {
		return Signature{}, fmt.Errorf("dkim2: DKIM2-Signature: %w", err)
	}
	i, err := positive(t["i"])
	if err != nil {
		return Signature{}, fmt.Errorf("dkim2: invalid i=: %w", err)
	}
	m, err := positive(t["m"])
	if err != nil {
		return Signature{}, fmt.Errorf("dkim2: invalid m=: %w", err)
	}
	time, err := decimal(t["t"])
	if err != nil {
		return Signature{}, fmt.Errorf("dkim2: invalid t=: %w", err)
	}
	domain := t["d"]
	if !validDomain(domain) {
		return Signature{}, errors.New("dkim2: invalid d= domain")
	}
	if t["s"] == "" {
		return Signature{}, errors.New("dkim2: missing s= signatures")
	}
	sig := Signature{Index: i, Instance: m, Timestamp: time, Domain: domain, Raw: raw, NextDomain: t["nd"], Nonce: t["n"]}
	if sig.Nonce != "" && !validNonce(sig.Nonce) {
		return Signature{}, errors.New("dkim2: invalid n= nonce")
	}
	_, hasND := t["nd"]
	_, hasMF := t["mf"]
	_, hasRT := t["rt"]
	if hasND {
		if !validDomain(sig.NextDomain) || hasMF || hasRT {
			return Signature{}, errors.New("dkim2: nd= conflicts with mf=/rt=")
		}
	} else {
		if !hasMF || !hasRT || t["mf"] == "" || t["rt"] == "" {
			return Signature{}, errors.New("dkim2: missing mf= or rt=")
		}
		mf, err := b64(t["mf"])
		if err != nil || !validPath(string(mf), true) {
			return Signature{}, errors.New("dkim2: invalid mf= path")
		}
		sig.MailFrom = string(mf)
		for _, encoded := range strings.Split(t["rt"], ",") {
			decoded, err := b64(encoded)
			if err != nil || !validPath(string(decoded), false) {
				return Signature{}, errors.New("dkim2: invalid rt= path")
			}
			sig.Recipients = append(sig.Recipients, string(decoded))
		}
	}
	seen := make(map[string]bool)
	for _, group := range strings.Split(t["s"], "|") {
		var sets []SignatureValue
		for _, entry := range strings.Split(group, ",") {
			parts := strings.Split(entry, ":")
			if len(parts) != 3 {
				return Signature{}, errors.New("dkim2: invalid s= signature set")
			}
			selector, algo, value := strings.Trim(parts[0], " \t"), strings.Trim(parts[1], " \t"), stripWSP(parts[2])
			if !validDomain(selector) || !validTextString(algo) || value == "" || seen[selector] {
				return Signature{}, errors.New("dkim2: invalid or duplicate selector")
			}
			seen[selector] = true
			decoded, err := b64(value)
			if err != nil {
				return Signature{}, fmt.Errorf("dkim2: invalid signature base64: %w", err)
			}
			if algo == "ed25519-sha256" && len(decoded) != ed25519.SignatureSize {
				return Signature{}, errors.New("dkim2: incorrect Ed25519 signature length")
			}
			if algo == "mldsa44" && len(decoded) != mldsa44.SignatureSize {
				return Signature{}, errors.New("dkim2: incorrect ML-DSA-44 signature length")
			}
			set := SignatureValue{selector, algo, value}
			sig.Values = append(sig.Values, set)
			sets = append(sets, set)
		}
		sig.ValueGroups = append(sig.ValueGroups, sets)
	}
	if f, present := t["f"]; present {
		if f == "" {
			return Signature{}, errors.New("dkim2: empty f= flag list")
		}
		for _, flag := range strings.Split(f, ",") {
			flag = strings.Trim(flag, " \t")
			if !validTextString(flag) {
				return Signature{}, errors.New("dkim2: empty flag")
			}
			sig.Flags = append(sig.Flags, flag)
		}
	}
	return sig, nil
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validPath(p string, nullOK bool) bool {
	if p == "<>" {
		return nullOK
	}
	if len(p) < 3 || p[0] != '<' || p[len(p)-1] != '>' || strings.ContainsAny(p, "\r\n\x00") {
		return false
	}
	inner := p[1 : len(p)-1]
	if !nullOK && strings.EqualFold(inner, "Postmaster") {
		return true
	}
	if strings.HasPrefix(inner, "@") {
		route, mailbox, ok := strings.Cut(inner, ":")
		if !ok || mailbox == "" {
			return false
		}
		for _, domain := range strings.Split(route, ",") {
			if len(domain) < 2 || domain[0] != '@' || !validDomain(domain[1:]) {
				return false
			}
		}
		inner = mailbox
	}
	at := strings.LastIndexByte(inner, '@')
	return at > 0 && (validDomain(inner[at+1:]) || validAddressLiteral(inner[at+1:])) && validLocalPart(inner[:at])
}

func validAddressLiteral(s string) bool {
	if len(s) < 3 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	value := s[1 : len(s)-1]
	if strings.HasPrefix(strings.ToLower(value), "ipv6:") {
		return strings.Contains(value[5:], ":") && net.ParseIP(value[5:]) != nil
	}
	if !strings.Contains(value, ":") {
		parts := strings.Split(value, ".")
		if len(parts) != 4 {
			return false
		}
		for _, part := range parts {
			if len(part) < 1 || len(part) > 3 {
				return false
			}
			for i := range part {
				if part[i] < '0' || part[i] > '9' {
					return false
				}
			}
			n, _ := strconv.Atoi(part)
			if n > 255 {
				return false
			}
		}
		return true
	}
	tag, content, ok := strings.Cut(value, ":")
	if !ok || !validDomain(tag) || strings.Contains(tag, ".") || content == "" {
		return false
	}
	for i := range content {
		c := content[i]
		if c < 33 || c > 126 || c == '[' || c == ']' || c == '\\' {
			return false
		}
	}
	return true
}

func validLocalPart(s string) bool {
	if len(s) == 0 || !utf8.ValidString(s) {
		return false
	}
	if s[0] == '"' {
		if len(s) < 2 || s[len(s)-1] != '"' {
			return false
		}
		for i := 1; i < len(s)-1; i++ {
			c := s[i]
			if c == '\\' {
				i++
				if i >= len(s)-1 || s[i] < 32 || s[i] == 127 {
					return false
				}
				continue
			}
			if c < 32 || c == 127 || c == '"' || c == '\\' {
				return false
			}
		}
		return true
	}
	if s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' || c >= 128 || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func validNonce(s string) bool {
	if len(s) > 64 {
		return false
	}
	for i := range s {
		if s[i] < 33 || s[i] > 126 || s[i] == ';' {
			return false
		}
	}
	return true
}

func pathDomain(p string) string {
	if p == "<>" {
		return ""
	}
	at := strings.LastIndexByte(p, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(p[at+1 : len(p)-1])
}

func domainMatch(child, parent string) bool {
	child, parent = strings.ToLower(child), strings.ToLower(parent)
	return child == parent || strings.HasSuffix(child, "."+parent)
}

var unsignedFields = map[string]bool{
	"apparently-to": true, "arc-authentication-results": true, "arc-message-signature": true,
	"arc-seal": true, "authentication-results": true,
	"delivered-to": true, "dkim-signature": true, "dl-expansion-history": true,
	"original-recipient": true, "received": true, "return-path": true,
	"sio-label-history": true, "x400-received": true, "x400-trace": true,
	"message-instance": true, "dkim2-signature": true,
}

func unsigned(name string) bool {
	return unsignedFields[name] || strings.HasPrefix(name, "received-") || strings.HasPrefix(name, "x-")
}

func collapseWSP(s string) string {
	var b strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func canonicalHeader(raw string, signature bool) (string, error) {
	s, err := unfold(raw)
	if err != nil {
		return "", err
	}
	name, value, ok := strings.Cut(s, ":")
	if !ok {
		return "", errors.New("missing colon")
	}
	name = strings.ToLower(name)
	if signature {
		return name + ":" + stripWSP(value) + "\r\n", nil
	}
	value = collapseWSP(value)
	return name + ":" + strings.Trim(value, " ") + "\r\n", nil
}

func headerDigest(headers []string, algorithm string) (string, error) {
	type item struct {
		name, value string
		order       int
	}
	var fields []item
	for i, raw := range headers {
		name, _, _ := strings.Cut(raw, ":")
		name = strings.ToLower(name)
		if unsigned(name) {
			continue
		}
		canonical, err := canonicalHeader(raw, false)
		if err != nil {
			return "", err
		}
		fields = append(fields, item{name, canonical, i})
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].name == fields[j].name {
			return fields[i].order > fields[j].order
		}
		return fields[i].name < fields[j].name
	})
	var b strings.Builder
	for _, field := range fields {
		b.WriteString(field.value)
	}
	return digest([]byte(b.String()), algorithm)
}

func bodyDigest(body []byte, algorithm string) (string, error) {
	// DKIM2 uses DKIM1 simple body canonicalization.
	for bytes.HasSuffix(body, []byte("\r\n")) {
		body = body[:len(body)-2]
	}
	canonical := make([]byte, 0, len(body)+2)
	canonical = append(canonical, body...)
	canonical = append(canonical, '\r', '\n')
	return digest(canonical, algorithm)
}

func digest(data []byte, algorithm string) (string, error) {
	switch algorithm {
	case "sha256":
		sum := sha256.Sum256(data)
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512(data)
		return base64.StdEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("dkim2: unsupported hash %q", algorithm)
	}
}

func validateStructure(m *Message) error {
	if len(m.Instances) == 0 || len(m.Signatures) == 0 {
		return errors.New("dkim2: missing Message-Instance or DKIM2-Signature")
	}
	for i, inst := range m.Instances {
		if inst.Number != i+1 {
			return fmt.Errorf("dkim2: missing or duplicate Message-Instance m=%d", i+1)
		}
	}
	lastM := 0
	signed := make([]bool, len(m.Instances))
	for i, sig := range m.Signatures {
		if sig.Index != i+1 {
			return fmt.Errorf("dkim2: missing or duplicate DKIM2-Signature i=%d", i+1)
		}
		if i == 0 && hasFlag(sig.Flags, "exploded") {
			return errors.New("dkim2: DKIM2-Signature i=1 has exploded flag")
		}
		if sig.Instance < lastM || sig.Instance > len(m.Instances) {
			return fmt.Errorf("dkim2: invalid m= in signature i=%d", sig.Index)
		}
		lastM = sig.Instance
		signed[sig.Instance-1] = true
	}
	if lastM != len(m.Instances) {
		return errors.New("dkim2: latest Message-Instance is unsigned")
	}
	for i, ok := range signed {
		if !ok {
			return fmt.Errorf("dkim2: Message-Instance m=%d is not signed", i+1)
		}
	}
	return nil
}
