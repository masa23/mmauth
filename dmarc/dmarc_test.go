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
				AggregateReportURI: []ReportURI{{URI: "mailto:agg@example.com", MaxSize: 0}},
				ForensicReportURI:  []ReportURI{{URI: "mailto:for@example.com", MaxSize: 0}},
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
				AggregateReportURI: []ReportURI{{URI: "mailto:abuse@example.jp", MaxSize: 0}},
				ForensicReportURI:  []ReportURI{{URI: "mailto:abuse@example.jp", MaxSize: 0}},
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
				AggregateReportURI: []ReportURI{{URI: "mailto:abuse@example.jp", MaxSize: 0}},
				ForensicReportURI:  []ReportURI{{URI: "mailto:abuse@example.jp", MaxSize: 0}},
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
			want: &Record{
				Version: "DMARC1",
				Policy:  "reject",
				AggregateReportURI: []ReportURI{
					{URI: "mailto:rua1@example.jp", MaxSize: 0},
					{URI: "mailto:rua2@example.jp", MaxSize: 0},
				},
				ForensicReportURI: []ReportURI{
					{URI: "mailto:ruf1@example.jp", MaxSize: 0},
					{URI: "mailto:rfu2@example.jp", MaxSize: 0},
				},
				raw: "v=DMARC1; p=reject; rua=mailto:rua1@example.jp, mailto:rua2@example.jp; ruf=mailto:ruf1@example.jp, mailto:rfu2@example.jp;",
			},
			resolver: func(name string) ([]string, error) {
				if name == "_dmarc.example.jp" {
					return []string{"v=DMARC1; p=reject; rua=mailto:rua1@example.jp, mailto:rua2@example.jp; ruf=mailto:ruf1@example.jp, mailto:rfu2@example.jp;"}, nil
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

func TestParseReportURI(t *testing.T) {
	testCases := []struct {
		name      string
		uri       string
		expected  *ReportURI
		wantError bool
	}{
		{
			name: "Simple URI without size limit",
			uri:  "mailto:reports@example.com",
			expected: &ReportURI{
				URI:     "mailto:reports@example.com",
				MaxSize: 0,
			},
			wantError: false,
		},
		{
			name: "URI with bytes limit",
			uri:  "mailto:reports@example.com!1024",
			expected: &ReportURI{
				URI:     "mailto:reports@example.com",
				MaxSize: 1024,
			},
			wantError: false,
		},
		{
			name: "URI with kilobytes limit (2^10)",
			uri:  "mailto:reports@example.com!50k",
			expected: &ReportURI{
				URI:     "mailto:reports@example.com",
				MaxSize: 50 << 10, // 51200
			},
			wantError: false,
		},
		{
			name: "URI with megabytes limit (2^20)",
			uri:  "mailto:reports@example.com!50m",
			expected: &ReportURI{
				URI:     "mailto:reports@example.com",
				MaxSize: 50 << 20, // 52428800
			},
			wantError: false,
		},
		{
			name: "URI with gigabytes limit (2^30)",
			uri:  "https://reports.example.com/dmarc!2g",
			expected: &ReportURI{
				URI:     "https://reports.example.com/dmarc",
				MaxSize: 2 << 30, // 2147483648
			},
			wantError: false,
		},
		{
			name: "URI with terabytes limit (2^40)",
			uri:  "https://reports.example.com/dmarc!1t",
			expected: &ReportURI{
				URI:     "https://reports.example.com/dmarc",
				MaxSize: 1 << 40, // 1099511627776
			},
			wantError: false,
		},
		{
			name:      "Invalid URI - empty",
			uri:       "",
			wantError: true,
		},
		{
			name:      "Invalid URI - only size limit",
			uri:       "!50m",
			wantError: true,
		},
		{
			name:      "Invalid URI - empty URI with size",
			uri:       " !50m",
			wantError: true,
		},
		{
			name:      "Invalid size unit",
			uri:       "mailto:reports@example.com!50x",
			wantError: true,
		},
		{
			name:      "Invalid size number",
			uri:       "mailto:reports@example.com!abc",
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReportURI(tc.uri)
			if tc.wantError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got == nil {
				t.Fatalf("Expected ReportURI but got nil")
			}
			if got.URI != tc.expected.URI {
				t.Errorf("URI mismatch: expected %q, got %q", tc.expected.URI, got.URI)
			}
			if got.MaxSize != tc.expected.MaxSize {
				t.Errorf("MaxSize mismatch: expected %d, got %d", tc.expected.MaxSize, got.MaxSize)
			}
		})
	}
}

func TestParseRecord_pTagRequired(t *testing.T) {
	// pタグがないDMARCレコードはRFC 7489 Section 6.3.7によりエラーにならなければならない
	testCases := []struct {
		name    string
		record  string
		wantErr bool
	}{
		{
			name:    "Missing p tag - record without policy",
			record:  "v=DMARC1; rua=mailto:reports@example.com;",
			wantErr: true,
		},
		{
			name:    "Missing p tag - only version",
			record:  "v=DMARC1;",
			wantErr: true,
		},
		{
			name:    "Valid record with p tag",
			record:  "v=DMARC1; p=none;",
			wantErr: false,
		},
		{
			name:    "Valid record with all tags",
			record:  "v=DMARC1; p=reject; rua=mailto:reports@example.com!50m; rf=afrf;",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecord(tc.record)
			if tc.wantErr && err == nil {
				t.Errorf("Expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestParseRecord_rfTag(t *testing.T) {
	// rfタグのパースと有効な値のフィルタリングをテスト
	testCases := []struct {
		name           string
		record         string
		expectedFormat []ReportFormat
	}{
		{
			name:           "Valid afrf format",
			record:         "v=DMARC1; p=reject; rf=afrf;",
			expectedFormat: []ReportFormat{ReportFormatAFRF},
		},
		{
			name:           "Multiple formats with afrf",
			record:         "v=DMARC1; p=reject; rf=afrf:unknown",
			expectedFormat: []ReportFormat{ReportFormatAFRF}, // unknownは無視される
		},
		{
			name:           "Unknown format only",
			record:         "v=DMARC1; p=reject; rf=unknown",
			expectedFormat: nil, // unknownは無視される
		},
		{
			name:           "Empty rf tag",
			record:         "v=DMARC1; p=reject; rf=",
			expectedFormat: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseRecord(tc.record)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !reflect.DeepEqual(rec.ReportFormat, tc.expectedFormat) {
				t.Errorf("ReportFormat mismatch: expected %v, got %v", tc.expectedFormat, rec.ReportFormat)
			}
		})
	}
}

func TestParseRecord_URIWithSizeLimit(t *testing.T) {
	// URIにサイズ指定がある場合のパースをテスト
	testCases := []struct {
		name               string
		record             string
		expectedRUACount   int
		expectedRUAMaxSize int64
		expectedRUFCount   int
		expectedRUFMaxSize int64
	}{
		{
			name:               "URI with megabytes size limit",
			record:             "v=DMARC1; p=none; rua=mailto:reports@example.com!50m; ruf=mailto:forensics@example.com!10m;",
			expectedRUACount:   1,
			expectedRUAMaxSize: 50 << 20,
			expectedRUFCount:   1,
			expectedRUFMaxSize: 10 << 20,
		},
		{
			name:               "Multiple URIs with size limits",
			record:             "v=DMARC1; p=none; rua=mailto:reports1@example.com!10k, mailto:reports2@example.com!20m;",
			expectedRUACount:   2,
			expectedRUAMaxSize: 20 << 20, // 2番目のURIのサイズ
			expectedRUFCount:   0,
			expectedRUFMaxSize: 0,
		},
		{
			name:               "URI without size limit",
			record:             "v=DMARC1; p=none; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com;",
			expectedRUACount:   1,
			expectedRUAMaxSize: 0,
			expectedRUFCount:   1,
			expectedRUFMaxSize: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseRecord(tc.record)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(rec.AggregateReportURI) != tc.expectedRUACount {
				t.Errorf("AggregateReportURI count mismatch: expected %d, got %d", tc.expectedRUACount, len(rec.AggregateReportURI))
			}
			if len(rec.ForensicReportURI) != tc.expectedRUFCount {
				t.Errorf("ForensicReportURI count mismatch: expected %d, got %d", tc.expectedRUFCount, len(rec.ForensicReportURI))
			}
			if tc.expectedRUACount > 0 {
				// 複数URIがある場合、最後のURIのサイズを確認
				lastURI := rec.AggregateReportURI[len(rec.AggregateReportURI)-1]
				if lastURI.MaxSize != tc.expectedRUAMaxSize {
					t.Errorf("Last RUA MaxSize mismatch: expected %d, got %d", tc.expectedRUAMaxSize, lastURI.MaxSize)
				}
			}
			if tc.expectedRUFCount > 0 {
				lastURI := rec.ForensicReportURI[len(rec.ForensicReportURI)-1]
				if lastURI.MaxSize != tc.expectedRUFMaxSize {
					t.Errorf("Last RUF MaxSize mismatch: expected %d, got %d", tc.expectedRUFMaxSize, lastURI.MaxSize)
				}
			}
		})
	}
}
