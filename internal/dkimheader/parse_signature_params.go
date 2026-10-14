package dkimheader

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseSignatureParams parses DKIM-Signature header parameters with strict validation
// according to RFC 6376 requirements.
func ParseSignatureParams(s string) (map[string]string, error) {
	if err := validateTagListCharacters(s); err != nil {
		return nil, err
	}
	pairs := strings.Split(s, ";")
	params := make(map[string]string)

	// Track seen tags to detect duplicates
	seenTags := make(map[string]bool)
	// RFC 6376 §3.5 requires v= but does not constrain its position. The
	// first-tag rule in §3.6.1 applies to DKIM key records only.

	for index, pair := range pairs {
		trimmedPair := strings.TrimSpace(pair)
		if trimmedPair == "" {
			if index == len(pairs)-1 && index > 0 {
				continue // one optional trailing semicolon
			}
			return nil, errors.New("malformed header params")
		}

		key, value, ok := strings.Cut(trimmedPair, "=")
		if !ok {
			return nil, errors.New("malformed header params")
		}

		trimmedKey := strings.TrimSpace(key)

		// Check for empty tag name
		if !validTagName(trimmedKey) {
			return nil, errors.New("malformed header params")
		}

		trimmedValue := strings.TrimSpace(value)

		// Check for duplicate tags (RFC 6376 §3.2 requires meticulous validation)
		if seenTags[trimmedKey] {
			return nil, fmt.Errorf("duplicate tag '%s' in DKIM-Signature header", trimmedKey)
		}
		seenTags[trimmedKey] = true

		// According to RFC 6376 §3.2, unrecognized tags MUST be ignored
		// Only process recognized tags
		if isValidDKIMTag(trimmedKey) {
			params[trimmedKey] = trimmedValue
		}
	}

	// Validate required tags for DKIM-Signature according to RFC 6376
	// All of the following tags are required: a, b, bh, d, h, s, v
	// Note: v is explicitly required according to RFC 6376 Section 3.5
	requiredTags := []string{"a", "b", "bh", "d", "h", "s", "v"}
	for _, tag := range requiredTags {
		if _, exists := params[tag]; !exists {
			return nil, fmt.Errorf("required tag '%s' is missing in DKIM-Signature header", tag)
		}
	}

	// Validate v tag value (RFC 6376 requires version to be "1")
	if params["v"] != "1" {
		return nil, fmt.Errorf("invalid version tag value: %s", params["v"])
	}
	for _, tag := range []string{"d", "s"} {
		if strings.IndexAny(params[tag], " \t\r\n") >= 0 {
			return nil, fmt.Errorf("invalid %s= identifier", tag)
		}
	}
	for _, rawName := range strings.Split(params["h"], ":") {
		name := strings.Trim(rawName, " \t\r\n")
		if name == "" || strings.IndexAny(name, " \t\r\n") >= 0 {
			return nil, fmt.Errorf("invalid h= signed header name")
		}
	}
	// RFC 6376 §3.5 permits FWS around a= but not inside its algorithm.
	if strings.IndexAny(params["a"], " \t\r\n") >= 0 {
		return nil, fmt.Errorf("invalid algorithm tag value: %q", params["a"])
	}
	if canonicalization, present := params["c"]; present {
		// An explicit c= needs an algorithm; the simple/simple default only
		// applies when c= is absent. RFC 6376 permits no FWS inside this value.
		if canonicalization == "" || strings.IndexAny(canonicalization, " \t\r\n") >= 0 {
			return nil, fmt.Errorf("invalid canonicalization tag value: %q", canonicalization)
		}
	}
	if methods, present := params["q"]; present {
		for _, rawMethod := range strings.Split(methods, ":") {
			method := strings.Trim(rawMethod, " \t\r\n")
			if method == "" {
				return nil, fmt.Errorf("invalid query method tag value: %q", methods)
			}
			if strings.EqualFold(method, "dns/txt") {
				continue
			}
			name, args, hasArgs := strings.Cut(method, "/")
			if !validHyphenatedWord(name) || (hasArgs && !validDKIMQuotedPrintable(args)) {
				return nil, fmt.Errorf("invalid query method tag value: %q", methods)
			}
		}
	}

	// Type validation for specific tags
	if err := validateTagTypes(params); err != nil {
		return nil, err
	}

	return params, nil
}

func validHyphenatedWord(value string) bool {
	if value == "" || !isASCIIAlpha(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		ch := value[i]
		if !isASCIIAlpha(ch) && (ch < '0' || ch > '9') && ch != '-' {
			return false
		}
	}
	return value[len(value)-1] != '-'
}

// RFC 6376 §2.11 permits FWS and extra '/' characters in extension args,
// but every '=' must begin an uppercase hexadecimal escape.
func validDKIMQuotedPrintable(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch ch {
		case '=':
			if i+2 >= len(value) || !isUpperHex(value[i+1]) || !isUpperHex(value[i+2]) {
				return false
			}
			i += 2
		case ' ', '\t', '\r', '\n':
			// validateTagListCharacters already checked that CRLF is FWS.
		default:
			if !((ch >= '!' && ch <= ':') || ch == '<' || (ch >= '>' && ch <= '~')) {
				return false
			}
		}
	}
	return true
}

func isUpperHex(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'F'
}

func validateTagListCharacters(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("invalid DKIM tag-list UTF-8")
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\r' {
			if i+2 >= len(value) || value[i+1] != '\n' || (value[i+2] != ' ' && value[i+2] != '\t') {
				return errors.New("invalid DKIM tag-list folding")
			}
			i++
			continue
		}
		if ch == '\n' || (ch < ' ' && ch != '\t') || ch > '~' {
			return errors.New("invalid DKIM tag-list character")
		}
	}
	return nil
}

func validTagName(name string) bool {
	if name == "" || !isASCIIAlpha(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		ch := name[i]
		if !isASCIIAlpha(ch) && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return true
}

func isASCIIAlpha(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
}

// isValidDKIMTag checks if a tag is a recognized DKIM-Signature tag according to RFC 6376
func isValidDKIMTag(tag string) bool {
	// Valid DKIM-Signature tags as defined in RFC 6376 §3.5
	validTags := map[string]bool{
		"v":  true, // Version
		"a":  true, // Algorithm
		"b":  true, // Signature
		"bh": true, // Body hash
		"c":  true, // Canonicalization
		"d":  true, // Domain
		"h":  true, // Headers
		"i":  true, // Identity
		"l":  true, // Length
		"q":  true, // Query
		"s":  true, // Selector
		"t":  true, // Timestamp
		"x":  true, // Expiration
		"z":  true, // Copied headers
	}
	_, exists := validTags[tag]
	return exists
}

// validateTagTypes performs type checking for DKIM-Signature tags
func validateTagTypes(params map[string]string) error {
	// Validate t and x tags (timestamps) - must be integers
	if tVal, exists := params["t"]; exists {
		if len(tVal) > 12 || !isUnsignedDecimal(tVal) {
			return fmt.Errorf("invalid timestamp 't' value: %s", tVal)
		}
		if _, err := strconv.ParseInt(tVal, 10, 64); err != nil {
			return fmt.Errorf("invalid timestamp 't' value: %s", tVal)
		}
	}

	if xVal, exists := params["x"]; exists {
		if len(xVal) > 12 || !isUnsignedDecimal(xVal) {
			return fmt.Errorf("invalid expiration 'x' value: %s", xVal)
		}
		if _, err := strconv.ParseInt(xVal, 10, 64); err != nil {
			return fmt.Errorf("invalid expiration 'x' value: %s", xVal)
		}
	}

	// Validate l tag (body length) - must be non-negative integer
	if lVal, exists := params["l"]; exists {
		if !isUnsignedDecimal(lVal) {
			return fmt.Errorf("invalid body length 'l' value: %s", lVal)
		}
		l, err := strconv.ParseInt(lVal, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid body length 'l' value: %s", lVal)
		}
		if l < 0 {
			return fmt.Errorf("body length 'l' must be non-negative: %d", l)
		}
		// Prevent extremely large values that could cause memory issues
		if l > 1<<32 { // Limit to 4GB
			return fmt.Errorf("body length 'l' value too large: %d", l)
		}
	}

	return nil
}

func isUnsignedDecimal(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
