package authres

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseARCInstance reads only the ARC instance prefix. ARC chain validation
// authenticates the remaining payload as raw bytes, even when it is malformed.
func ParseARCInstance(value string) (int, string, error) {
	end, depth := -1, 0
	quoted, escaped := false, false
	for i := 0; i < len(value); i++ {
		if escaped {
			escaped = false
			continue
		}
		if value[i] == '\\' && (quoted || depth > 0) {
			escaped = true
			continue
		}
		if value[i] == '"' && depth == 0 {
			quoted = !quoted
			continue
		}
		if quoted {
			continue
		}
		switch value[i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return 0, "", fmt.Errorf("invalid AAR instance tag")
			}
			depth--
		case ';':
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 || depth != 0 || quoted || escaped {
		return 0, "", fmt.Errorf("AAR instance tag is missing")
	}
	if err := ValidateFieldValue(value[:end]); err != nil {
		return 0, "", err
	}
	key, number, ok := strings.Cut(stripComments(unfold(value[:end])), "=")
	if !ok || strings.TrimSpace(key) != "i" {
		return 0, "", fmt.Errorf("AAR instance tag is missing")
	}
	number = strings.TrimSpace(number)
	if len(number) == 0 || len(number) > 2 {
		return 0, "", fmt.Errorf("invalid instance number")
	}
	for i := 0; i < len(number); i++ {
		if number[i] < '0' || number[i] > '9' {
			return 0, "", fmt.Errorf("invalid instance number")
		}
	}
	instance, err := strconv.Atoi(number)
	if err != nil || instance < 1 || instance > 50 {
		return 0, "", fmt.Errorf("invalid instance number")
	}
	return instance, value[end+1:], nil
}
