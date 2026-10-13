package dkimheader

import "testing"

const rfc6376BaseTags = "v=1; a=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj"

func TestRFC6376TagListABNFAndFWS(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"ordinary", rfc6376BaseTags, true},
		{"version after another tag", "a=rsa-sha256; v=1; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", true},
		{"folded separators", "v=1;\r\n a=rsa-sha256; d=example.com; s=test; h=from; bh=YW\r\n Jj; b=YWJj", true},
		{"FWS inside algorithm", "v=1; a=rsa -sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
		{"folded algorithm", "v=1; a=rsa-\r\n sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
		{"empty explicit canonicalization", rfc6376BaseTags + "; c=", false},
		{"canonicalization internal FWS", rfc6376BaseTags + "; c=relaxed / relaxed", false},
		{"query method internal FWS", rfc6376BaseTags + "; q=dns / txt", false},
		{"query method folded colon", rfc6376BaseTags + "; q=future \r\n : \r\n dns/txt", true},
		{"query extension argument FWS", rfc6376BaseTags + "; q=dns/t xt:dns/txt", true},
		{"query extension additional slash", rfc6376BaseTags + "; q=future/a/b:dns/txt", true},
		{"query extension encoded space", rfc6376BaseTags + "; q=future/a=20b:dns/txt", true},
		{"query extension bad escape", rfc6376BaseTags + "; q=future/a=ZZ:dns/txt", false},
		{"query extension lowercase escape", rfc6376BaseTags + "; q=future/a=2eb:dns/txt", false},
		{"12-digit timestamp", rfc6376BaseTags + "; t=999999999999", true},
		{"13-digit timestamp", rfc6376BaseTags + "; t=1000000000000", false},
		{"12-digit expiration", rfc6376BaseTags + "; x=999999999999", true},
		{"13-digit expiration", rfc6376BaseTags + "; x=1000000000000", false},
		{"unknown uppercase tag distinct", rfc6376BaseTags + "; W=one; w=two", true},
		{"empty repeated separator", rfc6376BaseTags + ";; z=one", false},
		{"leading separator", "; " + rfc6376BaseTags, false},
		{"invalid name hyphen", rfc6376BaseTags + "; x-y=one", false},
		{"invalid name starting digit", rfc6376BaseTags + "; 2x=one", false},
		{"bare LF", "v=1;\na=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
		{"bare CR", "v=1;\ra=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
		{"CRLF without WSP", "v=1;\r\na=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
		{"control", rfc6376BaseTags + "; z=a\x01b", false},
		{"invalid UTF-8", rfc6376BaseTags + "; z=" + string([]byte{0xff}), false},
		{"non-ASCII unknown tag", rfc6376BaseTags + "; z=é", false},
		{"uppercase required tag ignored", "V=1; a=rsa-sha256; d=example.com; s=test; h=from; bh=YWJj; b=YWJj", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignatureParams(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("input=%q error=%v; valid=%t", tc.input, err, tc.valid)
			}
		})
	}
}
