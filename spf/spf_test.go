package spf

import (
	"testing"
)

func TestIsValidDomainSpec(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid domain with macro",
			input:    "_spfh.%{d2}",
			expected: true,
		},
		{
			name:     "Valid FQDN",
			input:    "example.com",
			expected: true,
		},
		{
			name:     "Invalid single label",
			input:    "singlelabel",
			expected: false,
		},
		{
			name:     "Invalid characters",
			input:    "example$.com",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidDomainSpec(tc.input)
			if result != tc.expected {
				t.Errorf("isValidDomainSpec(%q) = %v; expected %v", tc.input, result, tc.expected)
			}
		})
	}
}
