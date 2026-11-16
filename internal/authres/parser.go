package authres

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// unfold replaces RFC 5322 folding whitespace without changing the raw field.
func unfold(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if i+2 < len(value) && value[i] == '\r' && value[i+1] == '\n' && (value[i+2] == ' ' || value[i+2] == '\t') {
			out.WriteByte(' ')
			i += 2
			for i+1 < len(value) && (value[i+1] == ' ' || value[i+1] == '\t') {
				i++
			}
			continue
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

// split separates the authserv-id and result entries. A
// semicolon inside a comment or quoted property is data, not a delimiter.
func split(value string) ([]string, error) {
	var fields []string
	start, depth := 0, 0
	quoted, escaped := false, false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && (quoted || depth > 0) {
			escaped = true
			continue
		}
		if quoted {
			if ch == '"' {
				quoted = false
			}
			continue
		}
		if depth > 0 {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '(':
			depth = 1
		case ')':
			return nil, fmt.Errorf("unbalanced authentication result comment")
		case ';':
			fields = append(fields, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	if quoted || depth != 0 || escaped {
		return nil, fmt.Errorf("unterminated authentication result quoted string or comment")
	}
	fields = append(fields, strings.TrimSpace(value[start:]))
	return fields, nil
}

func stripComments(value string) string {
	var out strings.Builder
	depth, quoted, escaped := 0, false, false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if escaped {
			if depth == 0 {
				out.WriteByte(ch)
			}
			escaped = false
			continue
		}
		if ch == '\\' && (quoted || depth > 0) {
			if depth == 0 {
				out.WriteByte(ch)
			}
			escaped = true
			continue
		}
		if quoted {
			out.WriteByte(ch)
			if ch == '"' {
				quoted = false
			}
			continue
		}
		if depth > 0 {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			}
			continue
		}
		if ch == '(' {
			depth = 1
			out.WriteByte(' ')
		} else {
			out.WriteByte(ch)
			if ch == '"' {
				quoted = true
			}
		}
	}
	return strings.TrimSpace(out.String())
}

func isMIMEToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch <= ' ' || ch >= 127 || strings.ContainsRune("()<>@,;:/[]?=", rune(ch)) || ch == '\\' || ch == '"' {
			return false
		}
	}
	return true
}

func isAuthServID(value string) bool {
	value = stripComments(value)
	if value == "" {
		return false
	}
	end := 0
	if value[0] == '"' {
		end = 1
		escaped := false
		closed := false
		for end < len(value) {
			ch := value[end]
			end++
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				closed = true
				break
			}
		}
		if !closed {
			return false
		}
		if end < len(value) && value[end] != ' ' && value[end] != '\t' {
			return false // RFC 8601 requires CFWS before authres-version.
		}
	} else {
		for end < len(value) && value[end] != ' ' && value[end] != '\t' {
			end++
		}
		if !isMIMEToken(value[:end]) && !isDomainName(value[:end]) {
			return false
		}
	}
	version := strings.TrimSpace(value[end:])
	if version == "" {
		return true
	}
	for i := 0; i < len(version); i++ {
		if version[i] < '0' || version[i] > '9' {
			return false
		}
	}
	return true
}

func isMethodResult(field string) bool {
	field = stripComments(field)
	i := skipWSP(field, 0)
	start := i
	i = scanKeyword(field, i)
	if i == start {
		return false
	}
	i = skipWSP(field, i)
	if i < len(field) && field[i] == '/' {
		i = skipWSP(field, i+1)
		start = i
		for i < len(field) && field[i] >= '0' && field[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	i = skipWSP(field, i)
	if i >= len(field) || field[i] != '=' {
		return false
	}
	i = skipWSP(field, i+1)
	start = i
	i = scanKeyword(field, i)
	if i == start {
		return false
	}
	seenReason, seenProperty := false, false
	for i < len(field) {
		if field[i] != ' ' && field[i] != '\t' {
			return false
		}
		i = skipWSP(field, i)
		start = i
		i = scanKeyword(field, i)
		if i == start {
			return false
		}
		name := field[start:i]
		i = skipWSP(field, i)
		if strings.EqualFold(name, "reason") && i < len(field) && field[i] == '=' {
			if seenReason || seenProperty {
				return false
			}
			seenReason = true
			i = skipWSP(field, i+1)
			i = scanValue(field, i, false)
			if i < 0 {
				return false
			}
			continue
		}
		if i >= len(field) || field[i] != '.' {
			return false
		}
		seenProperty = true
		i = skipWSP(field, i+1)
		start = i
		i = scanKeyword(field, i)
		if i == start {
			return false
		}
		i = skipWSP(field, i)
		if i >= len(field) || field[i] != '=' {
			return false
		}
		i = skipWSP(field, i+1)
		i = scanValue(field, i, true)
		if i < 0 {
			return false
		}
	}
	return true
}

func skipWSP(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func scanKeyword(s string, i int) int {
	// RFC 8601 refers to RFC 5321's Keyword = Ldh-str: hyphens may lead
	// but not end a keyword, and underscores are not allowed.
	start := i
	for i < len(s) {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
			i++
		} else {
			break
		}
	}
	if i == start || s[i-1] == '-' {
		return start
	}
	return i
}

// scanValue consumes an RFC 8601 value or an email-identity pvalue.
// A quoted local part may be followed by @domain-name.
func scanValue(s string, i int, property bool) int {
	if i >= len(s) {
		return -1
	}
	start := i
	if s[i] == '"' {
		i++
		closed := false
		for i < len(s) {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == '"' {
				i++
				closed = true
				break
			}
			if s[i] < ' ' || s[i] == 127 {
				return -1
			}
			i++
		}
		if !closed {
			return -1
		}
		if property && i < len(s) && s[i] == '@' {
			i++
			domainStart := i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			if !isDomainName(s[domainStart:i]) {
				return -1
			}
		}
	} else {
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		value := s[start:i]
		if !isMIMEToken(value) {
			if !property || !isEmailIdentity(value) {
				return -1
			}
		}
	}
	if i < len(s) && s[i] != ' ' && s[i] != '\t' {
		return -1
	}
	return i
}

func isEmailIdentity(value string) bool {
	local, domain, ok := strings.Cut(value, "@")
	if ok {
		if local != "" && !isLocalPart(local) {
			return false
		}
		return isDomainName(domain)
	}
	return isDomainName(value)
}

func isLocalPart(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, atom := range strings.Split(value, ".") {
		if atom == "" {
			return false
		}
		for _, r := range atom {
			if r > 127 {
				if unicode.IsControl(r) || unicode.IsSpace(r) {
					return false
				}
				continue
			}
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", r) {
				return false
			}
		}
	}
	return true
}

func isDomainName(value string) bool {
	if value == "" || !strings.Contains(value, ".") || !utf8.ValidString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}
	return true
}

// ValidateFieldValue checks controls, folding, and UTF-8 across a complete
// authentication result value, including any ARC instance prefix.
func ValidateFieldValue(value string) error {
	for i := 0; i < len(value); i++ {
		if (value[i] < ' ' && value[i] != '\r' && value[i] != '\n' && value[i] != '\t') || value[i] == 127 {
			return fmt.Errorf("invalid authentication result control character")
		}
		if value[i] == '\r' {
			if i+2 >= len(value) || value[i+1] != '\n' || (value[i+2] != ' ' && value[i+2] != '\t') {
				return fmt.Errorf("invalid authentication result line folding")
			}
			i++
		} else if value[i] == '\n' {
			return fmt.Errorf("invalid authentication result line folding")
		}
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("invalid authentication result UTF-8")
	}
	return nil
}

// ParsePayload validates an RFC 8601 authserv-id and its result entries.
func ParsePayload(value string) (string, []string, error) {
	if err := ValidateFieldValue(value); err != nil {
		return "", nil, err
	}
	fields, err := split(unfold(value))
	if err != nil {
		return "", nil, err
	}
	if len(fields) < 2 {
		return "", nil, fmt.Errorf("authserv-id or result is missing")
	}
	if !isAuthServID(fields[0]) {
		return "", nil, fmt.Errorf("invalid authserv-id")
	}
	if strings.EqualFold(stripComments(fields[1]), "none") {
		if len(fields) != 2 {
			return "", nil, fmt.Errorf("none cannot be combined with results")
		}
		return stripComments(fields[0]), fields[1:], nil
	}
	for _, field := range fields[1:] {
		if !isMethodResult(field) {
			return "", nil, fmt.Errorf("invalid method result: %q", field)
		}
	}
	return stripComments(fields[0]), fields[1:], nil
}

func ValidAuthServID(value string) bool { return isAuthServID(value) }

func ValidMethodResult(value string) bool { return isMethodResult(value) }

func IsNoneResult(value string) bool {
	return strings.EqualFold(stripComments(value), "none")
}
