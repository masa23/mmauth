package mmauth

import (
	"fmt"
	"net"
	"strings"

	"github.com/masa23/mmauth/internal/authres"
)

// AuthenticationResults is one complete RFC 8601 field. Raw retains the
// original bytes so callers can preserve trace header order and folding.
type AuthenticationResults struct {
	AuthServID string
	Version    string // "1" when omitted
	Results    []string
	Raw        string
}

// ParseAuthenticationResults validates one complete Authentication-Results
// field, including its authserv-id, optional version, and result entries.
func ParseAuthenticationResults(field string) (*AuthenticationResults, error) {
	name, value, ok := strings.Cut(field, ":")
	if !ok || !strings.EqualFold(name, "Authentication-Results") {
		return nil, fmt.Errorf("invalid Authentication-Results field name")
	}
	if !strings.HasSuffix(value, "\r\n") {
		return nil, fmt.Errorf("Authentication-Results field must end with CRLF")
	}
	idValue, results, err := authres.ParsePayload(value[:len(value)-2])
	if err != nil {
		return nil, fmt.Errorf("invalid Authentication-Results field: %w", err)
	}
	id, version := splitAuthServVersion(idValue)
	if id == "" {
		return nil, fmt.Errorf("invalid Authentication-Results authserv-id")
	}
	return &AuthenticationResults{
		AuthServID: id, Version: version, Results: append([]string(nil), results...), Raw: field,
	}, nil
}

func splitAuthServVersion(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	end := 0
	if value[0] == '"' {
		end = 1
		escaped := false
		for end < len(value) {
			ch := value[end]
			end++
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				break
			}
		}
	} else {
		for end < len(value) && value[end] != ' ' && value[end] != '\t' {
			end++
		}
	}
	version := strings.TrimSpace(value[end:])
	if version == "" {
		version = "1"
	}
	return value[:end], version
}

// FormatAuthenticationResults constructs a complete RFC 8601 field. With no
// result entries it emits the exclusive "none" result.
func FormatAuthenticationResults(authServID string, results []string) (string, error) {
	if !authres.ValidAuthServID(authServID) {
		return "", fmt.Errorf("invalid Authentication-Results authserv-id")
	}
	if len(results) == 0 {
		results = []string{"none"}
	}
	for _, fragment := range results {
		if !authres.ValidMethodResult(fragment) && !authres.IsNoneResult(fragment) {
			return "", fmt.Errorf("invalid Authentication-Results result")
		}
	}
	field := "Authentication-Results: " + authServID + "; " + strings.Join(results, ";\r\n\t") + "\r\n"
	if _, err := ParseAuthenticationResults(field); err != nil {
		return "", err
	}
	return field, nil
}

// GetAuthenticationResultsField evaluates SPF and formats the current
// DKIM/ARC results as one complete field for the caller to prepend.
func (m *MMAuth) GetAuthenticationResultsField(authServID string, remoteAddr net.IP, helo, mailFrom string) (string, error) {
	if m == nil || m.AuthenticationHeaders == nil {
		return "", fmt.Errorf("authentication results are unavailable")
	}
	return FormatAuthenticationResults(authServID, m.GetAuthenticationHeader(remoteAddr, helo, mailFrom))
}

// FilterAuthenticationResults prepares message headers at an ADMD boundary.
// An untrusted source loses every Authentication-Results field, as permitted
// by RFC 8601 §5. Trusted sources keep syntactically valid version 1 fields;
// unsupported versions and malformed fields are removed. Other fields retain
// their original order and bytes. The caller decides whether the source is
// trusted and prepends any newly generated field after filtering.
func FilterAuthenticationResults(fields []string, trustedSource bool) []string {
	filtered := make([]string, 0, len(fields))
	for _, field := range fields {
		name, _, ok := strings.Cut(field, ":")
		if ok && strings.EqualFold(strings.TrimRight(name, " \t"), "Authentication-Results") {
			if !trustedSource {
				continue
			}
			parsed, err := ParseAuthenticationResults(field)
			if err != nil || parsed.Version != "1" {
				continue
			}
		}
		filtered = append(filtered, field)
	}
	return filtered
}
