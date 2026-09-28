package dmarc_test

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/masa23/mmauth/dmarc"
)

func TestEffectivePolicyJSON(t *testing.T) {
	old := dmarc.DefaultResolver
	defer func() { dmarc.DefaultResolver = old }()
	for _, tc := range []struct {
		record       string
		exact, child dmarc.PolicyType
	}{
		{"v=DMARC1; p=none; sp=reject", dmarc.PolicyNone, dmarc.PolicyReject},
		{"v=DMARC1; p=reject; sp=none", dmarc.PolicyReject, dmarc.PolicyNone},
		{"v=DMARC1; p=reject; sp=quarantine", dmarc.PolicyReject, dmarc.PolicyQuarantine},
		{"v=DMARC1; p=reject", dmarc.PolicyReject, dmarc.PolicyReject},
	} {
		dmarc.DefaultResolver = func(name string) ([]string, error) {
			if name == "_dmarc.example.com" {
				return []string{tc.record}, nil
			}
			return nil, &net.DNSError{IsNotFound: true}
		}
		for _, domain := range []string{"example.com", "sub.example.com"} {
			t.Run(tc.record+"/"+domain, func(t *testing.T) {
				r, err := dmarc.LookupRecordWithSubdomainFallback(domain)
				if err != nil {
					t.Fatal(err)
				}
				want, inherited := tc.exact, domain != "example.com"
				if inherited {
					want = tc.child
				}
				buf, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				var restored dmarc.Record
				if err := json.Unmarshal(buf, &restored); err != nil {
					t.Fatal(err)
				}
				for _, record := range []*dmarc.Record{r, &restored} {
					if record.EffectivePolicy() != want || record.IsSubdomainPolicy != inherited {
						t.Fatalf("policy=%s inherited=%t want=%s/%t JSON=%s", record.EffectivePolicy(), record.IsSubdomainPolicy, want, inherited, buf)
					}
				}
			})
		}
	}
}
