package arc

import (
	"fmt"
	"strings"

	"github.com/masa23/mmauth/internal/authres"
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

// ARC-Authentication-Results の文字列化
// ヘッダ名は含まない
func (aar ARCAuthenticationResults) String() string {
	results := aar.Results
	if len(results) == 0 {
		results = []string{"none"}
	}
	return fmt.Sprintf("i=%d; %s; %s", aar.InstanceNumber, aar.AuthServId, strings.Join(results, ";\r\n        "))
}

// ParseARCAuthenticationResults extracts the instance and the RFC 8601
// assessment entries, preserving signed raw bytes for seal validation.
func ParseARCAuthenticationResults(s string) (*ARCAuthenticationResults, error) {
	name, value, ok := strings.Cut(s, ":")
	if !ok || !strings.EqualFold(name, "ARC-Authentication-Results") {
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
