package dkimheader

import "strings"

// ValidBase64String checks RFC 6376 §2.10 after the enclosing tag-list has
// already been checked for valid FWS.
func ValidBase64String(value string) bool {
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return false
	}
	padding := false
	count := 0
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '=' {
			padding = true
			count++
			if count > 2 {
				return false
			}
			continue
		}
		if padding || !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '+' || ch == '/') {
			return false
		}
	}
	return true
}
