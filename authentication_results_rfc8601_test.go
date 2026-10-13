package mmauth

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/masa23/mmauth/spf"
)

func TestRFC8601CompleteAuthenticationResultsField(t *testing.T) {
	for _, tc := range []struct {
		name, raw, wantID, wantVersion string
		wantResults                    []string
	}{
		{"multiple methods", "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;\r\n\t dkim=pass header.d=example.com\r\n", "mx.example.com", "1", []string{"spf=pass smtp.mailfrom=example.com", "dkim=pass header.d=example.com"}},
		{"no authentication", "Authentication-Results: mx.example.com; none\r\n", "mx.example.com", "1", []string{"none"}},
		{"explicit version", "Authentication-Results: mx.example.com 2; dkim=pass\r\n", "mx.example.com", "2", []string{"dkim=pass"}},
		{"quoted identifier and comments", "Authentication-Results: \"mx; edge\" (trusted) 1; dkim=pass (ok) header.d=example.com\r\n", "\"mx; edge\"", "1", []string{"dkim=pass (ok) header.d=example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAuthenticationResults(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.AuthServID != tc.wantID || got.Version != tc.wantVersion || !reflect.DeepEqual(got.Results, tc.wantResults) || got.Raw != tc.raw {
				t.Fatalf("parsed=%+v", got)
			}
		})
	}
	generated, err := FormatAuthenticationResults("mx.example.com", []string{"spf=pass smtp.mailfrom=example.com", "dkim=pass header.d=example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if generated != "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;\r\n\tdkim=pass header.d=example.com\r\n" {
		t.Fatalf("generated=%q", generated)
	}
	none, err := FormatAuthenticationResults("mx.example.com", nil)
	if err != nil || none != "Authentication-Results: mx.example.com; none\r\n" {
		t.Fatalf("none=%q error=%v", none, err)
	}
}

func TestRFC8601AuthenticationResultsRejectsMalformedAndInjection(t *testing.T) {
	for _, raw := range []string{
		"Authentication-Results: mx.example.com; none; dkim=pass\r\n",
		"Authentication-Results: mx.example.com; garbage\r\n",
		"Authentication-Results: mx.example.com; dkim=pass\r\nInjected: yes\r\n",
		"Authentication-Results: mx.example.com; dkim=pass\nspf=pass\r\n",
		"Authentication-Results: mx.example.com; dkim=pass\x01\r\n",
		"Authentication-Results: mx.example.com; none\v\r\n",
		"Authentication-Results: mx.example.com; dkim=pass",
		"Authentication-Results : mx.example.com; dkim=pass\r\n",
		"From: mx.example.com; dkim=pass\r\n",
	} {
		if _, err := ParseAuthenticationResults(raw); err == nil {
			t.Errorf("accepted malformed field %q", raw)
		}
	}
	for _, tc := range []struct {
		id      string
		results []string
	}{
		{"mx.example.com\r\nInjected: yes", []string{"spf=pass"}},
		{"mx.example.com; dkim=pass", []string{"spf=pass"}},
		{"mx.example.com", []string{"spf=pass\r\nInjected: yes"}},
		{"mx.example.com", []string{"none", "dkim=pass"}},
	} {
		if field, err := FormatAuthenticationResults(tc.id, tc.results); err == nil {
			t.Errorf("accepted id=%q results=%q as %q", tc.id, tc.results, field)
		}
	}
}

func TestRFC8601BoundaryRemovesForgedResultsAndPreservesTraceOrder(t *testing.T) {
	fields := []string{
		"Received: from relay.example.net\r\n",
		"Authentication-Results: mx.example.com; dkim=pass\r\n",
		"From: a@example.com\r\n",
		"AUTHENTICATION-RESULTS: outside.example.net; spf=pass\r\n",
		"Authentication-Results: mx.example.com 2; dkim=pass\r\n",
		"Authentication-Results: mx.example.com; none\r\n",
	}
	if got := FilterAuthenticationResults(fields, false); !reflect.DeepEqual(got, []string{fields[0], fields[2]}) {
		t.Fatalf("untrusted filtered=%q", got)
	}
	if got := FilterAuthenticationResults(fields, true); !reflect.DeepEqual(got, []string{fields[0], fields[1], fields[2], fields[3], fields[5]}) {
		t.Fatalf("trusted filtered=%q", got)
	}
	if len(fields) != 6 {
		t.Fatal("filter mutated input")
	}
}

func TestRFC8601PublicCompleteFieldUsesCurrentAuthenticationResults(t *testing.T) {
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 +all"}, nil }
	m := NewMMAuth()
	if _, err := m.Write([]byte("From: a@example.com\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	field, err := m.GetAuthenticationResultsField("mx.example.com", net.ParseIP("192.0.2.1"), "helo.example.net", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(field, "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;") {
		t.Fatalf("field=%q", field)
	}
	if _, err := ParseAuthenticationResults(field); err != nil {
		t.Fatalf("generated field is not parseable: %v", err)
	}
}
