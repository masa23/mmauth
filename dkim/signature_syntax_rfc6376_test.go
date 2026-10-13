package dkim

import (
	"strings"
	"testing"
)

func TestRFC6376SignatureIdentityAndBase64Syntax(t *testing.T) {
	base := "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj"
	for _, tc := range []struct {
		name, replace, with string
		valid               bool
	}{
		{"empty local-part", "b=YWJj", "i=@example.com; b=YWJj", true},
		{"quoted local-part", "b=YWJj", `i="a=20b"@example.com; b=YWJj`, true},
		{"quoted escape", "b=YWJj", `i="a=5C"b"@example.com; b=YWJj`, true},
		{"unquoted encoded space", "b=YWJj", "i=a=20b@example.com; b=YWJj", false},
		{"double dot local-part", "b=YWJj", "i=a..b@example.com; b=YWJj", false},
		{"bad quoted printable hex", "b=YWJj", "i=a=2eb@example.com; b=YWJj", false},
		{"trailing QP escape", "b=YWJj", "i=a=2@example.com; b=YWJj", false},
		{"folded signature and body hash", "bh=YWJj; b=YWJj", "bh=YW\r\n Jj; b=YW\r\n Jj", true},
		{"bad signature alphabet", "b=YWJj", "b=YW_Jj", false},
		{"bad body hash padding", "bh=YWJj", "bh=Y= WJj", false},
		{"missing body hash", "bh=YWJj", "bh=", false},
		{"bad signature FWS", "b=YWJj", "b=YW\r\nJj", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(base, tc.replace, tc.with, 1)
			_, err := ParseSignature(input)
			if (err == nil) != tc.valid {
				t.Fatalf("input=%q error=%v; valid=%t", input, err, tc.valid)
			}
		})
	}
}

func TestRFC6376SignatureFieldNameBoundary(t *testing.T) {
	const value = "v=1; a=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj"
	for _, name := range []string{" DKIM-Signature", "DKIM-Signature "} {
		if _, err := ParseSignature(name + ": " + value); err == nil {
			t.Fatalf("invalid field name %q accepted", name)
		}
	}
}
