package spf

import (
	"net"
	"testing"
)

// RFC 7208 §§4.5–4.6.1 separates the version and terms with SP, not HTAB.
func TestRFC7208SPFVersionAndTermSeparators(t *testing.T) {
	original := DefaultTXTResolver
	t.Cleanup(func() { DefaultTXTResolver = original })
	for _, tc := range []struct {
		name    string
		records []string
		want    Status
	}{
		{"SP delimiter", []string{"v=spf1 -all"}, Fail},
		{"leading SP is not an SPF record", []string{" v=spf1 -all"}, None},
		{"HTAB after version is not an SPF record", []string{"v=spf1\t-all"}, None},
		{"invalid candidate does not create multiple SPF records", []string{"v=spf1\t-all", "v=spf1 -all"}, Fail},
		{"HTAB between terms is a syntax error", []string{"v=spf1 -all\t?all"}, PermError},
		{"trailing HTAB is a syntax error", []string{"v=spf1 -all\t"}, PermError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			DefaultTXTResolver = func(name string) ([]string, error) {
				if name != "example.com" {
					t.Fatalf("unexpected DNS query: %q", name)
				}
				return tc.records, nil
			}
			got := CheckSPF(net.ParseIP("192.0.2.1"), "example.com", "a@example.com", "helo.example.com")
			if got.Status != tc.want {
				t.Fatalf("CheckSPF(%q) = %s, want %s", tc.records, got.Status, tc.want)
			}
		})
	}
}
