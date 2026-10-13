package domainkey

import (
	"context"
	"errors"
	"net"
	"testing"
)

type recordingTXTResolver struct {
	queries []string
	records []string
	err     error
}

func (r *recordingTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.queries = append(r.queries, name)
	return r.records, r.err
}

func TestRFC6376DKIMKeyLookupQueryAndResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []string
		err     error
		wantKey string
		wantErr error
	}{
		{"one key", []string{"v=DKIM1; k=rsa; p=AQAB"}, nil, "AQAB", nil},
		{"no TXT record", nil, nil, "", ErrNoRecordFound},
		{"NXDOMAIN", nil, &net.DNSError{IsNotFound: true}, "", ErrNoRecordFound},
		{"temporary DNS failure", nil, &net.DNSError{IsTemporary: true}, "", ErrDNSLookupFailed},
		// RFC 6376 §6.1 step 4 permits choosing one of multiple key records.
		// This implementation chooses the first usable record.
		{"multiple keys", []string{"v=DKIM1; k=rsa; p=AQAB", "v=DKIM1; k=rsa; p=AgMB"}, nil, "AQAB", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &recordingTXTResolver{records: tc.records, err: tc.err}
			key, err := LookupDKIMDomainKeyWithResolver("mail", "example.com", resolver)
			if len(resolver.queries) != 1 || resolver.queries[0] != "mail._domainkey.example.com" {
				t.Fatalf("queries=%v", resolver.queries)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("lookup error=%v, want %v", err, tc.wantErr)
			}
			if key.PublicKey != tc.wantKey {
				t.Fatalf("public key=%q, want %q", key.PublicKey, tc.wantKey)
			}
		})
	}
}
