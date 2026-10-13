package mmauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
)

func TestRFC6376PublicVerifyResults(t *testing.T) {
	message := rfc8463MessageWithCRLF()
	oldResolver := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = oldResolver }()
	for _, tc := range []struct {
		name      string
		message   string
		dnsError  error
		want      dkim.VerifyStatus
		wantCalls int
	}{
		{"valid", message, nil, dkim.VerifyStatusPass, 2},
		{"modified header", strings.Replace(message, "Joe SixPack", "Eve SixPack", 1), nil, dkim.VerifyStatusFail, 2},
		{"temporary DNS failure", message, errors.New("temporary DNS failure"), dkim.VerifyStatusTempErr, 2},
		{"no signature", "Date: Tue, 05 Feb 2019 00:00:00 +0000\r\nFrom: a@example.com\r\n\r\n", nil, dkim.VerifyStatusNone, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			domainkey.DefaultResolver = func(name string) ([]string, error) {
				calls++
				if tc.dnsError != nil {
					return nil, tc.dnsError
				}
				switch name {
				case "brisbane._domainkey.football.example.com":
					return []string{rfc8463EdRecord}, nil
				case "test._domainkey.football.example.com":
					return []string{rfc8463RSARecord}, nil
				default:
					t.Fatalf("unexpected DNS query %q", name)
					return nil, nil
				}
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte(tc.message)); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m.Verify()
			if got := m.AuthenticationHeaders.DKIMSignatures.GetResult(); got != tc.want || calls != tc.wantCalls {
				t.Fatalf("result=%s, want %s; DNS calls=%d, want %d", got, tc.want, calls, tc.wantCalls)
			}
		})
	}
}
