package mmauth

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/masa23/mmauth/internal/authres"
	"github.com/masa23/mmauth/spf"
)

func TestRFC8601SPFResultPropertiesAndSpecialCharacters(t *testing.T) {
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 +all"}, nil }
	m := &MMAuth{AuthenticationHeaders: &AuthenticationHeaders{}}
	for _, tc := range []struct {
		name, helo, mailFrom string
		want                 []string
	}{
		{"quoted local part and angle brackets", "helo.example.net", `<"a;b"@example.com>`, []string{`spf=pass smtp.mailfrom=example.com`}},
		{"invalid MAIL FROM cannot inject a header", "helo.example.net", "a@example.com\r\nInjected: yes", []string{"spf=none"}},
		{"invalid HELO cannot inject a result", "helo.example.net; dkim=pass", "<>", []string{"spf=none"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), tc.helo, tc.mailFrom)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("results=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestRFC8601SPFPropertyDomainSyntax(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"example.com", true},
		{"münchen.example", true},
		{strings.Repeat("a", 63) + ".example", true},
		{strings.Repeat("a", 64) + ".example", false},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
		{strings.Repeat("ü", 60) + ".example", false},
		{"localhost", false},
		{"-bad.example", false},
		{"bad-.example", false},
		{"bad..example", false},
		{"bad.example.", false},
		{"bad_example.com", false},
		{"bad.example; dkim=pass", false},
	} {
		if got := authres.ValidDomainValue(tc.value); got != tc.valid {
			t.Errorf("domain %q: valid=%v, want %v", tc.value, got, tc.valid)
		}
	}
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 +all"}, nil }
	m := &MMAuth{AuthenticationHeaders: &AuthenticationHeaders{}}
	helo := strings.Repeat("a", 64) + ".example"
	got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), helo, "<>")
	if len(got) != 1 || strings.Contains(got[0], "smtp.helo=") {
		t.Fatalf("overlong HELO leaked into Authentication-Results: %q", got)
	}
}

func TestRFC8601PublicResultFragmentOrder(t *testing.T) {
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 +all"}, nil }
	m := NewMMAuth()
	if _, err := m.Write([]byte("From: a@example.com\r\nDKIM-Signature: broken\r\nARC-Seal: broken\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.Verify()
	want := []string{
		"spf=pass smtp.mailfrom=example.com",
		"dkim=permerror reason=\"malformed signature\"",
		"arc=fail (malformed ARC headers)",
	}
	got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), "helo.example.net", "a@example.com")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results=%q, want %q", got, want)
	}
}
