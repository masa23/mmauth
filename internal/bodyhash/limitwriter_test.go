package bodyhash

import (
	"bytes"
	"testing"
)

func TestLimitWriter(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		limit       int64
		expected    string
		expectError bool
	}{
		{
			name:        "limit_zero",
			input:       "hello world",
			limit:       0,
			expected:    "",
			expectError: false,
		},
		{
			name:        "limit_less_than_input",
			input:       "hello world",
			limit:       5,
			expected:    "hello",
			expectError: false,
		},
		{
			name:        "limit_equal_to_input",
			input:       "hello world",
			limit:       11,
			expected:    "hello world",
			expectError: false,
		},
		{
			name:        "limit_greater_than_input",
			input:       "hello world",
			limit:       20,
			expected:    "hello world",
			expectError: false,
		},
		{
			name:        "negative_limit",
			input:       "hello world",
			limit:       -1,
			expected:    "",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			lw := newLimitWriter(&buf, tc.limit)

			_, err := lw.Write([]byte(tc.input))
			if (err != nil) != tc.expectError {
				t.Errorf("expected error: %v, got: %v", tc.expectError, err)
			}

			got := buf.String()
			if got != tc.expected {
				t.Errorf("expected: %q, got: %q", tc.expected, got)
			}
		})
	}
}
