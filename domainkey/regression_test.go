package domainkey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestRegressionServiceWildcard(t *testing.T) {
	k, e := ParseDomainKeyRecord("v=DKIM1; k=rsa; s=*; p=AA==")
	if e != nil {
		t.Fatal(e)
	}
	if !k.IsService(ServiceTypeEmail) {
		t.Error("s=* does not authorize email")
	}
}
func TestRegressionDNSError(t *testing.T) {
	old := DefaultResolver
	defer func() { DefaultResolver = old }()
	DefaultResolver = func(string) ([]string, error) {
		return nil, &net.DNSError{IsTimeout: true, IsTemporary: true, Err: "timeout"}
	}
	_, e := LookupDKIMDomainKey("s", "example.com")
	var dnsErr *net.DNSError
	if !errors.As(e, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("resolver error lost: %v", e)
	}
	if !errors.Is(e, ErrDNSLookupFailed) {
		t.Errorf("timeout mapped to no key: %v", e)
	}
}

type errorTXTResolver struct{ err error }

func (r errorTXTResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, r.err }
func TestDNSErrorWithResolver(t *testing.T) {
	for _, tc := range []struct{ err, want error }{
		{&net.DNSError{IsTimeout: true}, ErrDNSLookupFailed},
		{&net.DNSError{IsTemporary: true}, ErrDNSLookupFailed},
		{fmt.Errorf("wrapped: %w", &net.DNSError{IsNotFound: true}), ErrNoRecordFound},
	} {
		_, err := LookupDKIMDomainKeyWithResolver("s", "example.com", errorTXTResolver{tc.err})
		if !errors.Is(err, tc.want) {
			t.Errorf("lookup error=%v, want %v", err, tc.want)
		}
	}
}
