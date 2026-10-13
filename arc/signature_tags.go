package arc

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

type signatureTag struct {
	key, value string
}

// parseSignatureTags preserves tag order and checks the structure before any
// algorithm defaults are applied. An empty b= is used by signing placeholders.
func parseSignatureTags(value, fieldName string, required []string) ([]signatureTag, error) {
	if err := validateSignatureTagListCharacters(value); err != nil {
		return nil, fmt.Errorf("invalid %s tag-list: %w", fieldName, err)
	}
	var tags []signatureTag
	seen := make(map[string]string)
	fields := strings.Split(value, ";")
	for i, field := range fields {
		field = strings.Trim(field, " \t\r\n")
		if field == "" {
			if i == len(fields)-1 && i > 0 {
				continue // RFC 6376 permits one terminal semicolon.
			}
			return nil, fmt.Errorf("empty %s tag", fieldName)
		}
		key, value, ok := strings.Cut(field, "=")
		key = strings.Trim(key, " \t\r\n")
		if !ok || !validSignatureTagName(key) {
			return nil, fmt.Errorf("malformed %s tag", fieldName)
		}
		if i == 0 && key != "i" {
			return nil, fmt.Errorf("%s must begin with i=", fieldName)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate tag '%s' in %s", key, fieldName)
		}
		value = strings.Trim(value, " \t\r\n")
		switch key {
		case "b", "bh", "h":
			value = strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, value)
		case "d":
			if _, err := arcDNSName(value, 2); err != nil {
				return nil, fmt.Errorf("invalid %s d= tag: %w", fieldName, err)
			}
		case "s":
			if _, err := arcDNSName(value, 1); err != nil {
				return nil, fmt.Errorf("invalid %s s= tag: %w", fieldName, err)
			}
		}
		seen[key] = value
		tags = append(tags, signatureTag{key, value})
	}
	for _, key := range required {
		value, exists := seen[key]
		if !exists {
			return nil, fmt.Errorf("%s %s tag is missing", fieldName, key)
		}
		if value == "" && key != "b" {
			return nil, fmt.Errorf("%s %s tag is empty", fieldName, key)
		}
	}
	return tags, nil
}

func validSignatureTagName(name string) bool {
	if name == "" || !isASCIILetter(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		ch := name[i]
		if !isASCIILetter(ch) && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return true
}

func isASCIILetter(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

// arcDNSName validates the DKIM domain/selector grammar and converts any
// RFC 8617 U-labels to the A-labels needed for DNS lookup. The parsed header
// retains its original spelling for signature verification.
func arcDNSName(value string, minLabels int) (string, error) {
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("invalid DNS name")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < minLabels {
		return "", fmt.Errorf("invalid DNS name")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
				continue
			}
			if ch != '-' || i == 0 || i == len(label)-1 {
				return "", fmt.Errorf("invalid DNS label")
			}
		}
	}
	return ascii, nil
}

func validateSignatureTagListCharacters(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("invalid UTF-8")
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\r' {
			if i+2 >= len(value) || value[i+1] != '\n' || (value[i+2] != ' ' && value[i+2] != '\t') {
				return fmt.Errorf("invalid line folding")
			}
			i++
			continue
		}
		if ch == '\n' || (ch < ' ' && ch != '\t') || ch == 127 {
			return fmt.Errorf("invalid tag-list character")
		}
	}
	return nil
}
