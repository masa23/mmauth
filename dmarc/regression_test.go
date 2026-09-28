package dmarc

import (
	"errors"
	"net"
	"testing"
)

func TestRegressionDefaults(t *testing.T) {
	r, e := ParseRecord("v=DMARC1; p=reject")
	if e != nil {
		t.Fatal(e)
	}
	if r.Percent != 100 || r.AlignmentDKIM != AlignmentRelaxed || r.AlignmentSPF != AlignmentRelaxed || r.ReportInterval != 86400 {
		t.Errorf("missing defaults: pct=%d adkim=%q aspf=%q ri=%d", r.Percent, r.AlignmentDKIM, r.AlignmentSPF, r.ReportInterval)
	}
}
func TestRegressionSubdomainPolicy(t *testing.T) {
	old := DefaultResolver
	defer func() { DefaultResolver = old }()
	DefaultResolver = func(name string) ([]string, error) {
		if name == "_dmarc.example.com" {
			return []string{"v=DMARC1; p=reject"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	r, e := LookupRecordWithSubdomainFallback("sub.example.com")
	if e != nil {
		t.Fatalf("parent p=reject lost: %v", e)
	}
	if r.Policy != PolicyReject {
		t.Errorf("got %+v", r)
	}
}
func TestRegressionOrganizationalFallback(t *testing.T) {
	old := DefaultResolver
	defer func() { DefaultResolver = old }()
	DefaultResolver = func(name string) ([]string, error) {
		switch name {
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=reject; sp=reject"}, nil
		case "_dmarc.sub.example.com":
			return []string{"v=DMARC1; p=none; sp=none"}, nil
		}
		return nil, &net.DNSError{IsNotFound: true}
	}
	r, e := LookupRecordWithSubdomainFallback("deep.sub.example.com")
	if e != nil {
		t.Fatal(e)
	}
	if r.SubdomainPolicy != PolicyReject {
		t.Errorf("intermediate parent's policy used: %+v", r)
	}
}
func TestRegressionDNSError(t *testing.T) {
	old := DefaultResolver
	defer func() { DefaultResolver = old }()
	DefaultResolver = func(string) ([]string, error) {
		return nil, &net.DNSError{IsTimeout: true, IsTemporary: true, Err: "timeout"}
	}
	_, e := LookupRecord("example.com")
	var dnsErr *net.DNSError
	if !errors.As(e, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("resolver error lost: %v", e)
	}
	if !errors.Is(e, ErrDNSLookupFailed) {
		t.Errorf("timeout mapped to no record: %v", e)
	}
}

func TestFallbackStopsOnLookupError(t *testing.T) {
	old := DefaultResolver
	defer func() { DefaultResolver = old }()
	for _, tc := range []struct {
		records   []string
		err, want error
	}{
		{nil, &net.DNSError{IsTimeout: true}, ErrDNSLookupFailed},
		{[]string{"v=DMARC1; p=none", "v=DMARC1; p=reject"}, nil, ErrMultipleRecords},
	} {
		queries := 0
		DefaultResolver = func(name string) ([]string, error) { queries++; return tc.records, tc.err }
		_, err := LookupRecordWithSubdomainFallback("deep.sub.example.com")
		if !errors.Is(err, tc.want) || queries != 1 {
			t.Fatalf("err=%v queries=%d", err, queries)
		}
	}
}

func TestExplicitDMARCValuesAndEffectivePolicy(t *testing.T) {
	r, err := ParseRecord("v=DMARC1; p=reject; pct=0; adkim=s; aspf=s; ri=0; fo=1:d; rf=afrf; sp=quarantine")
	if err != nil {
		t.Fatal(err)
	}
	if r.Percent != 0 || r.ReportInterval != 0 || r.AlignmentDKIM != AlignmentStrict || r.AlignmentSPF != AlignmentStrict || len(r.FailureOptions) != 2 {
		t.Fatalf("explicit values replaced by defaults: %+v", r)
	}
	if r.EffectivePolicy() != PolicyReject {
		t.Fatal("exact-domain policy must use p")
	}
	r.IsSubdomainPolicy = true
	if r.EffectivePolicy() != PolicyQuarantine {
		t.Fatal("subdomain policy must use sp")
	}
}
