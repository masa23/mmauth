package arc

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/masa23/mmauth/internal/header"
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
		field = strings.TrimSpace(field)
		if field == "" {
			if i == len(fields)-1 && i > 0 {
				continue // RFC 6376 permits one terminal semicolon.
			}
			return nil, fmt.Errorf("empty %s tag", fieldName)
		}
		key, value, ok := strings.Cut(field, "=")
		key = strings.TrimSpace(key)
		if !ok || !validSignatureTagName(key) {
			return nil, fmt.Errorf("malformed %s tag", fieldName)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate tag '%s' in %s", key, fieldName)
		}
		value = header.StripWhiteSpace(value)
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
			return fmt.Errorf("invalid control character")
		}
	}
	return nil
}
