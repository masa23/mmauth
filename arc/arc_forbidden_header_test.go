package arc

import (
	"strings"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

// TestARCMessageSignature_Verify_ForbiddenHeaders tests that ARC-Message-Signature verification
// correctly rejects signatures that include forbidden headers in the h= tag.
func TestARCMessageSignature_Verify_ForbiddenHeaders(t *testing.T) {
	// Mock headers
	headers := []string{
		"From: alice@example.com\r\n",
		"To: bob@example.com\r\n",
		"Subject: Test\r\n",
	}

	// Mock body hash
	bodyHash := "dummyBodyHash"

	// Mock domain key
	domainKey := &domainkey.DomainKey{}

	testCases := []struct {
		name        string
		headers     string
		expectError bool
	}{
		{
			name:        "forbidden_authentication_results",
			headers:     "from:authentication-results",
			expectError: true,
		},
		{
			name:        "forbidden_arc_authentication_results",
			headers:     "from:arc-authentication-results",
			expectError: true,
		},
		{
			name:        "forbidden_arc_message_signature",
			headers:     "from:arc-message-signature",
			expectError: true,
		},
		{
			name:        "forbidden_arc_seal",
			headers:     "from:arc-seal",
			expectError: true,
		},
		{
			name:        "valid_headers",
			headers:     "from:to:subject",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create an ARCMessageSignature with forbidden headers in h= tag
			ams := &ARCMessageSignature{
				Headers:          tc.headers,
				Canonicalization: "simple/simple",
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header: CanonicalizationSimple,
				},
				raw: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector; h=" + tc.headers + "; bh=; b=",
			}

			// Call the Verify method
			result := ams.Verify(headers, bodyHash, domainKey)

			if tc.expectError {
				if result.Status() != VerifyStatusPermErr {
					t.Errorf("Expected VerifyStatusPermErr, got %s", result.Status())
				}

				expectedMessages := []string{
					"forbidden header authentication-results found in h= tag",
					"forbidden header arc-authentication-results found in h= tag",
					"forbidden header arc-message-signature found in h= tag",
					"forbidden header arc-seal found in h= tag",
				}

				found := false
				for _, msg := range expectedMessages {
					if strings.Contains(result.Message(), msg) {
						found = true
						break
					}
				}

				if !found {
					t.Errorf("Unexpected error message: %s", result.Message())
				}
			} else {
				// For valid headers, we expect a different error (like missing signature)
				// but not a forbidden header error
				if result.Status() == VerifyStatusPermErr &&
					(strings.Contains(result.Message(), "forbidden header") ||
						strings.Contains(result.Message(), "ARC-Message-Signature header field contains ARC-Seal")) {
					t.Errorf("Unexpected forbidden header error for valid headers: %s", result.Message())
				}
			}
		})
	}
}
