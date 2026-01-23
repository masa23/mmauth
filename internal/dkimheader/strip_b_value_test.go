package dkimheader

import (
	"testing"
)

func TestStripBValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple case",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=abc123; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
		{
			name:     "with spaces",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b= abc123 ; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
		{
			name:     "with tabs",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=\tabc123\t; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
		{
			name:     "multiline with folding",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=abc123\r\n def456; bh=ghi789",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=ghi789",
		},
		{
			name:     "no semicolon after b",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=abc123\r\n",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=\r\n",
		},
		{
			name:     "b at end with no value",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=",
		},
		{
			name:     "no b tag",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; bh=def456",
		},
		{
			name:     "b tag in middle",
			input:    "DKIM-Signature: v=1; b=abc123; a=rsa-sha256",
			expected: "DKIM-Signature: v=1; b=; a=rsa-sha256",
		},
		{
			name:     "multiple b tags - only first affected",
			input:    "DKIM-Signature: v=1; b=abc123; a=rsa-sha256; b=def456",
			expected: "DKIM-Signature: v=1; b=; a=rsa-sha256; b=def456",
		},
		{
			name:     "uppercase B tag",
			input:    "DKIM-Signature: v=1; B=abc123; a=rsa-sha256",
			expected: "DKIM-Signature: v=1; B=; a=rsa-sha256",
		},
		{
			name:     "mixed case",
			input:    "DKIM-Signature: v=1; b=AbC123; a=rsa-sha256",
			expected: "DKIM-Signature: v=1; b=; a=rsa-sha256",
		},
		{
			name:     "complex base64 value",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=dGVzdCB2YWx1ZQ==; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
		{
			name:     "b tag at beginning of value part",
			input:    "DKIM-Signature: v=1;\r\n b=abc123; a=rsa-sha256",
			expected: "DKIM-Signature: v=1;\r\n b=; a=rsa-sha256",
		},
		{
			name:     "empty b value",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
		{
			name:     "b value with special characters",
			input:    "DKIM-Signature: v=1; a=rsa-sha256; b=abc+123/456=; bh=def456",
			expected: "DKIM-Signature: v=1; a=rsa-sha256; b=; bh=def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripBValueForSigning(tt.input)
			if result != tt.expected {
				t.Errorf("StripBValueForSigning(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkStripBValue(b *testing.B) {
	input := "DKIM-Signature: v=1; a=rsa-sha256; b=dGVzdCB2YWx1ZQ==; bh=def456"

	for i := 0; i < b.N; i++ {
		StripBValueForSigning(input)
	}
}
