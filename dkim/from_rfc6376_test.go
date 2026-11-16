package dkim

import (
	"crypto/ed25519"
	"testing"
)

// RFC 6376 §5.4 requires every signer to include From in h=.
func TestRFC6376SignerRequiresFrom(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, tc := range []struct {
		name      string
		headers   []string
		wantError bool
	}{
		{"missing From", []string{"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"}, true},
		{"invalid From field name", []string{"From : a@example.com\r\n"}, true},
		{"case-insensitive From", []string{"fRoM: a@example.com\r\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "AAAA"}
			err := sig.Sign(tc.headers, key)
			if (err != nil) != tc.wantError {
				t.Fatalf("Sign() error = %v, wantError %t", err, tc.wantError)
			}
			if err == nil && sig.Headers != "fRoM" {
				t.Fatalf("signed headers = %q, want fRoM", sig.Headers)
			}
		})
	}
}
