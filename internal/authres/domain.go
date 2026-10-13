package authres

import (
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// ValidDomainValue checks a domain before placing it in an RFC 8601 property.
func ValidDomainValue(value string) bool {
	if !strings.Contains(value, ".") || !validLabels(value, true) {
		return false
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ascii) > 253 {
		return false
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || !validLabels(label, false) {
			return false
		}
	}
	return true
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
