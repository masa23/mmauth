package dmarc

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
)

func assertRecordEqual(t *testing.T, got, expected *Record) {
	t.Helper()
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("DMARC mismatch:\nExpected: %+v\nGot:      %+v", expected, got)
	}
}

func assertErrorEqual(t *testing.T, got, expected error) {
	t.Helper()
	if !errors.Is(got, expected) {
		t.Errorf("Expected error: %v, but got: %v", expected, got)
	}
}

func Test_getParentDomain(t *testing.T) {
	testCases := []struct {
		domain      string
		expected    string
		expectedErr bool
	}{
		{
			domain:   "example.com",
			expected: "example.com",
		},
		{
			domain:   "sub.example.com",
			expected: "example.com",
		},
		{
			domain:   "sub.sub.example.com",
			expected: "sub.example.com",
		},
		{
			domain:   "sub.sub.sub.example.com",
			expected: "sub.sub.example.com",
		},
		{
			domain:   "example.co.jp",
			expected: "example.co.jp",
		},
		{
			domain:   "sub.example.co.jp",
			expected: "example.co.jp",
		},
		{
			domain:   "sub.sub.example.co.jp",
			expected: "sub.example.co.jp",
		},
		{
			domain:      "com",
			expected:    "com",
			expectedErr: true,
		},
		{
			domain:      "",
			expected:    "",
			expectedErr: true,
		},
		{
			domain:   "example.sakura",
			expected: "example.sakura",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ParentDomain: %s", tc.domain), func(t *testing.T) {
			got, err := getParentDomain(tc.domain)
			if (err != nil) != tc.expectedErr {
				t.Fatalf("Expected error: %v, but got: %v", tc.expectedErr, err)
			}
			if err == nil && got != tc.expected {
				t.Fatalf("Expected: %s, but got: %s", tc.expected, got)
			}
		})
	}
}

func TestParseRecord(t *testing.T) {
	testCases := []struct {
		raw      string
		expected *Record
	}{
		{
			raw: "v=DMARC1; p=none; rua=mailto:agg@example.com; ruf=mailto:for@example.com; fo=1:d:s; adkim=s; aspf=r; pct=50; ri=3600; sp=quarantine;",
			expected: &Record{
				Version:            "DMARC1",
				Policy:             PolicyNone,
				SubdomainPolicy:    PolicyQuarantine,
				AggregateReportURI: []string{"mailto:agg@example.com"},
				ForensicReportURI:  []string{"mailto:for@example.com"},
				FailureOptions:     []FailureOption{"1", "d", "s"},
				AlignmentDKIM:      AlignmentStrict,
				AlignmentSPF:       AlignmentRelaxed,
				Percent:            50,
				ReportInterval:     3600,
				raw:                "v=DMARC1; p=none; rua=mailto:agg@example.com; ruf=mailto:for@example.com; fo=1:d:s; adkim=s; aspf=r; pct=50; ri=3600; sp=quarantine;",
			},
		},
		{
			raw: "v=DMARC1; p=reject; adkim=r; aspf=s;",
			expected: &Record{
				Version:       "DMARC1",
				Policy:        PolicyReject,
				AlignmentDKIM: AlignmentRelaxed,
				AlignmentSPF:  AlignmentStrict,
				raw:           "v=DMARC1; p=reject; adkim=r; aspf=s;",
			},
		},
		{
			raw: "v=DMARC1; p=quarantine; pct=100; ri=86400;",
			expected: &Record{
				Version:        "DMARC1",
				Policy:         PolicyQuarantine,
				Percent:        100,
				ReportInterval: 86400,
				raw:            "v=DMARC1; p=quarantine; pct=100; ri=86400;",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Parse: %s", tc.raw), func(t *testing.T) {
			got, err := ParseRecord(tc.raw)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			assertRecordEqual(t, got, tc.expected)
		})
	}
}

func TestLookupRecord(t *testing.T) {
	testCases := []struct {
		domain   string
		want     *Record
		wantErr  error
		resolver TXTLookupFunc
	}{
		{
			domain: "example.jp",
			want: &Record{
				Version:            "DMARC1",
				Policy:             "reject",
				AggregateReportURI: []string{"mailto:abuse@example.jp"},
				ForensicReportURI:  []string{"mailto:abuse@example.jp"},
				raw:                "v=DMARC1; p=reject; rua=mailto:abuse@example.jp; ruf=mailto:abuse@example.jp;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject; rua=mailto:abuse@example.jp; ruf=mailto:abuse@example.jp;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain: "example.jp",
			want:   nil,
			resolver: func(name string) ([]string, error) {
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: ErrNoRecordFound,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Lookup: %s", tc.domain), func(t *testing.T) {
			originalResolver := DefaultResolver
			t.Cleanup(func() {
				DefaultResolver = originalResolver
			})
			DefaultResolver = tc.resolver
			got, err := LookupRecord(tc.domain)
			assertErrorEqual(t, err, tc.wantErr)
			assertRecordEqual(t, got, tc.want)
		})
	}
}

func TestLookupRecordWithSubdomainFallback(t *testing.T) {
	testCases := []struct {
		domain   string
		want     *Record
		wantErr  error
		resolver TXTLookupFunc
	}{
		{
			domain: "example.jp",
			want: &Record{
				Version:            "DMARC1",
				Policy:             "reject",
				AggregateReportURI: []string{"mailto:abuse@example.jp"},
				ForensicReportURI:  []string{"mailto:abuse@example.jp"},
				raw:                "v=DMARC1; p=reject; rua=mailto:abuse@example.jp; ruf=mailto:abuse@example.jp;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject; rua=mailto:abuse@example.jp; ruf=mailto:abuse@example.jp;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain: "sub.example.jp",
			want: &Record{
				Version:           "DMARC1",
				Policy:            "reject",
				SubdomainPolicy:   "reject",
				isSubdomainPolicy: true,
				raw:               "v=DMARC1; p=reject; sp=reject;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject; sp=reject;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain: "sub.sub.example.jp",
			want: &Record{
				Version:           "DMARC1",
				Policy:            "reject",
				SubdomainPolicy:   "reject",
				isSubdomainPolicy: true,
				raw:               "v=DMARC1; p=reject; sp=reject;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject; sp=reject;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain: "sub.sub.example.jp",
			want: &Record{
				Version:           "DMARC1",
				Policy:            "reject",
				SubdomainPolicy:   "reject",
				isSubdomainPolicy: true,
				raw:               "v=DMARC1; p=reject; sp=reject;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.sub.example.jp" {
					return []string{"v=DMARC1; p=reject; sp=reject;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: nil,
		},
		{
			domain: "sub.example.jp",
			want:   nil,
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject;"}, nil
				}
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: ErrNoRecordFound,
		},
		{
			domain: "example.jp",
			want:   nil,
			resolver: func(name string) ([]string, error) {
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: ErrNoRecordFound,
		},
		{
			domain: "sub.example.jp",
			want:   nil,
			resolver: func(name string) ([]string, error) {
				return nil, &net.DNSError{IsNotFound: true}
			},
			wantErr: ErrNoRecordFound,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("LookupRecordWithSubdomainFallback: %s", tc.domain), func(t *testing.T) {
			originalResolver := DefaultResolver
			t.Cleanup(func() {
				DefaultResolver = originalResolver
			})
			DefaultResolver = tc.resolver
			got, err := LookupRecordWithSubdomainFallback(tc.domain)
			assertErrorEqual(t, err, tc.wantErr)
			assertRecordEqual(t, got, tc.want)
		})
	}
}
