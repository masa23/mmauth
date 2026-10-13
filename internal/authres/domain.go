package authres

import (
	"strings"
	"unicode"
)

// ValidDomainValue checks a domain before placing it in an RFC 8601 property.
func ValidDomainValue(value string) bool {
	return strings.Contains(value, ".") && validLabels(value, true)
}

// ValidSelectorValue accepts the ASCII labels used by header.s.
func ValidSelectorValue(value string) bool { return validLabels(value, false) }

func validLabels(value string, allowUnicode bool) bool {
	if value == "" {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return false
		}
		for i, r := range label {
			if (allowUnicode || r < 128) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
				continue
			}
			if r != '-' || i == 0 || i+1 == len(label) {
				return false
			}
		}
	}
	return true
}
