package arc

import (
	"fmt"
	"strings"

	"github.com/masa23/mmauth/internal/authres"
	"github.com/masa23/mmauth/internal/header"
)

// ARC-Authentication-Results の構造体
// 最低限の情報を保持する
type ARCAuthenticationResults struct {
	InstanceNumber int    // i
	AuthServId     string // Atuhentication Server Domain
	Results        []string
	raw            string
}

func (aar *ARCAuthenticationResults) Raw() string {
	if aar.raw == "" {
		return aar.String()
	}
	return aar.raw
}

// Format validates and returns the AAR field value without its header name.
func (aar ARCAuthenticationResults) Format() (string, error) {
	results := aar.Results
	if len(results) == 0 {
		results = []string{"none"}
	}
	value := fmt.Sprintf("i=%d; %s; %s", aar.InstanceNumber, aar.AuthServId, strings.Join(results, ";\r\n        "))
	if _, err := ParseARCAuthenticationResults("ARC-Authentication-Results: " + value + "\r\n"); err != nil {
		return "", err
	}
	return value, nil
}

// String returns the AAR field value, or an empty string for invalid values.
func (aar ARCAuthenticationResults) String() string {
	value, _ := aar.Format()
	return value
}

// ParseARCAuthenticationResults extracts the instance and the RFC 8601
// assessment entries, preserving signed raw bytes for seal validation.
func ParseARCAuthenticationResults(s string) (*ARCAuthenticationResults, error) {
	name, value, ok := strings.Cut(s, ":")
	if !ok || !header.EqualASCIIFold(name, "ARC-Authentication-Results") {
		return nil, fmt.Errorf("invalid header field")
	}
	value = strings.TrimSuffix(value, "\r\n")
	if err := authres.ValidateFieldValue(value); err != nil {
		return nil, err
	}
	instance, payload, err := authres.ParseARCInstance(value)
	if err != nil {
		return nil, err
	}
	id, results, err := authres.ParsePayload(payload)
	if err != nil {
		return nil, err
	}
	return &ARCAuthenticationResults{InstanceNumber: instance, AuthServId: id, Results: results, raw: s}, nil
}
