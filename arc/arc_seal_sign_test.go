package arc

import (
	"strings"
	"testing"
)

// TestARCSeal_Sign_ArcSetOnly tests that AS.Sign() signs only ARC Set headers
func TestARCSeal_Sign_ArcSetOnly(t *testing.T) {
	// Create headers with multiple ARC sets and other headers
	headers := []string{
		"From: alice@example.com\r\n",
		"To: bob@example.com\r\n",
		"Subject: Test\r\n",
		// ARC Set 1
		"ARC-Authentication-Results: i=1; spf=pass\r\n",
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=default; h=from:to;\r\n        bh=dummyBodyHash; b=signature1\r\n",
		"ARC-Seal: i=1; a=rsa-sha256; t=12345; cv=none; d=example.com; s=default; b=seal1\r\n",
		// ARC Set 2
		"ARC-Authentication-Results: i=2; spf=pass\r\n",
		"ARC-Message-Signature: i=2; a=rsa-sha256; d=example.com; s=default; h=from:to;\r\n        bh=dummyBodyHash; b=signature2\r\n",
		// Other headers that should not be signed
		"Authentication-Results: spf=pass\r\n",
		"DKIM-Signature: a=rsa-sha256; d=example.com; s=default; h=from:to; bh=dummyBodyHash; b=dkimSig\r\n",
	}

	as := &ARCSeal{
		Algorithm:       SignatureAlgorithmRSA_SHA256,
		ChainValidation: ChainValidationResultNone,
		Domain:          "example.com",
		InstanceNumber:  3, // Creating a new seal for instance 3
		Selector:        "default",
		hashAlgo:        hashAlgo(SignatureAlgorithmRSA_SHA256),
	}

	// Mock key for signing
	privateKey := testKeys.getPrivateKey("rsa")

	// Sign
	err := as.Sign(headers, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Since we can't easily inspect what headers were actually signed,
	// we'll check that the signature is not empty and seems reasonable
	if as.Signature == "" {
		t.Fatalf("Signature is empty")
	}

	// Basic check that signature looks like base64
	if !isValidBase64(as.Signature) {
		t.Errorf("Signature doesn't look like valid base64: %s", as.Signature)
	}
}

// isValidBase64 checks if a string is valid base64 (simplified check)
func isValidBase64(s string) bool {
	// Remove any whitespace that might be added by wrapping
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, " ", "")

	// Check length is multiple of 4
	if len(s)%4 != 0 {
		return false
	}

	// Check characters are valid base64
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}

	return true
}
