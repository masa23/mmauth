package domainkey

import "testing"

// RFC 6376 §§3.2, 3.6.1: tag names are case-sensitive, duplicate names
// invalidate the entire list, and an explicit v= must be first.
func TestRFC6376DomainKeyTagListRules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		record    string
		wantError bool
		wantKey   string
	}{
		{"version first", "v=DKIM1; p=AAAA", false, "AAAA"},
		{"trailing semicolon", "v=DKIM1; p=AAAA;", false, "AAAA"},
		{"version omitted", "p=AAAA", false, "AAAA"},
		{"folded public key", "v=DKIM1; p=AA\t\r\n BB", false, "AABB"},
		{"bare newline", "v=DKIM1; p=AA\nBB", true, ""},
		{"invalid UTF-8", "v=DKIM1; x=" + string([]byte{0xff}) + "; p=AAAA", true, ""},
		{"non-ASCII unknown tag", "v=DKIM1; x=é; p=AAAA", true, ""},
		{"leading semicolon", ";v=DKIM1; p=AAAA", true, ""},
		{"consecutive semicolons", "v=DKIM1;; p=AAAA", true, ""},
		{"two trailing semicolons", "v=DKIM1; p=AAAA;;", true, ""},
		{"missing equals", "v=DKIM1; unknown; p=AAAA", true, ""},
		{"empty tag name", "v=DKIM1; =one; p=AAAA", true, ""},
		{"invalid tag name", "v=DKIM1; x-y=one; p=AAAA", true, ""},
		{"duplicate key", "v=DKIM1; p=AAAA; p=BBBB", true, ""},
		{"duplicate unknown tag", "v=DKIM1; x=one; x=two; p=AAAA", true, ""},
		{"version after key", "p=AAAA; v=DKIM1", true, ""},
		{"uppercase key is unknown", "v=DKIM1; P=AAAA", false, ""},
		{"distinct case-sensitive names", "v=DKIM1; P=BBBB; p=AAAA", false, "AAAA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParseDomainKeyRecord(tc.record)
			if (err != nil) != tc.wantError {
				t.Fatalf("ParseDomainKeyRecord(%q) error = %v, wantError %t", tc.record, err, tc.wantError)
			}
			if err == nil && key.PublicKey != tc.wantKey {
				t.Fatalf("ParseDomainKeyRecord(%q) public key = %q, want %q", tc.record, key.PublicKey, tc.wantKey)
			}
		})
	}
}
