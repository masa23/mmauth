package mmauth

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/masa23/mmauth/spf"
)

func TestRFC7208PublicAuthenticationResultStatusesAndIdentity(t *testing.T) {
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	for _, tc := range []struct {
		name, mailFrom, record string
		err                    error
		want                   spf.Status
		wantLookup             string
		wantFragment           string
	}{
		{"pass", "a@example.com", "v=spf1 +all", nil, spf.Pass, "example.com", "spf=pass smtp.mailfrom=example.com"},
		{"fail", "a@example.com", "v=spf1 -all", nil, spf.Fail, "example.com", "spf=fail smtp.mailfrom=example.com"},
		{"softfail", "a@example.com", "v=spf1 ~all", nil, spf.SoftFail, "example.com", "spf=softfail smtp.mailfrom=example.com"},
		{"neutral", "a@example.com", "v=spf1 ?all", nil, spf.Neutral, "example.com", "spf=neutral smtp.mailfrom=example.com"},
		{"none", "a@example.com", "", nil, spf.None, "example.com", "spf=none smtp.mailfrom=example.com"},
		{"temperror", "a@example.com", "", errors.New("SERVFAIL"), spf.TempError, "example.com", "spf=temperror smtp.mailfrom=example.com"},
		{"permerror", "a@example.com", "v=spf1 bad-mechanism", nil, spf.PermError, "example.com", "spf=permerror smtp.mailfrom=example.com"},
		{"null reverse path", "<>", "v=spf1 +all", nil, spf.Pass, "helo.example.net", "spf=pass smtp.helo=helo.example.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lookups []string
			spf.DefaultTXTResolver = func(name string) ([]string, error) {
				lookups = append(lookups, name)
				if tc.record == "" {
					return nil, tc.err
				}
				return []string{tc.record}, tc.err
			}
			m := &MMAuth{AuthenticationHeaders: &AuthenticationHeaders{}}
			got := m.GetAuthenticationHeader(net.ParseIP("192.0.2.1"), "helo.example.net", tc.mailFrom)
			if !reflect.DeepEqual(got, []string{tc.wantFragment}) || m.AuthenticationHeaders.SPFResult == nil || m.AuthenticationHeaders.SPFResult.Status != tc.want || !reflect.DeepEqual(lookups, []string{tc.wantLookup}) {
				t.Fatalf("results=%v, SPF=%+v, lookups=%v; want %q/%s/%q", got, m.AuthenticationHeaders.SPFResult, lookups, tc.wantFragment, tc.want, tc.wantLookup)
			}
		})
	}
}
