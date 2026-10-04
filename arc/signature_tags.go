package arc

import (
	"fmt"
	"strings"

	"github.com/masa23/mmauth/internal/header"
)

type signatureTag struct {
	key, value string
}

// parseSignatureTags preserves tag order and checks the structure before any
// algorithm defaults are applied. An empty b= is used by signing placeholders.
func parseSignatureTags(value, fieldName string, required []string) ([]signatureTag, error) {
	var tags []signatureTag
	seen := make(map[string]string)
	for _, field := range strings.Split(value, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
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
