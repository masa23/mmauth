package dmarc

import (
	"errors"
	"reflect"
	"testing"
)

// RFC 7489 §6.6.3 recommends treating a record with an invalid p or sp and
// a syntactically valid rua as v=DMARC1; p=none during policy discovery.
func TestRFC7489InvalidPolicyWithAggregateURI(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	for _, tc := range []struct {
		name, raw string
		wantNone  bool
	}{
		{"invalid p", "v=DMARC1; p=bad; rua=mailto:r@example.net", true},
		{"uppercase report tag", "v=DMARC1; p=bad; RUA=mailto:r@example.net", true},
		{"invalid sp", "v=DMARC1; p=reject; sp=bad; rua=mailto:r@example.net", true},
		{"invalid optional before invalid sp", "v=DMARC1; p=reject; pct=101; sp=bad; rua=mailto:r@example.net", true},
		{"missing p", "v=DMARC1; rua=mailto:r@example.net", true},
		{"duplicate p", "v=DMARC1; p=reject; p=none; rua=mailto:r@example.net", true},
		{"duplicate sp", "v=DMARC1; p=reject; sp=reject; sp=none; rua=mailto:r@example.net", true},
		{"one valid rua among invalid entries", "v=DMARC1; p=bad; rua=mailto:bad%ZZ@example.net,mailto:r@example.net", true},
		{"valid rua after duplicate", "v=DMARC1; p=bad; rua=mailto:bad%ZZ@example.net; rua=mailto:r@example.net", true},
		{"invalid rua", "v=DMARC1; p=bad; rua=mailto:bad%ZZ@example.net", false},
		{"no rua", "v=DMARC1; p=bad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			DefaultResolver = func(name string) ([]string, error) {
				queries++
				if name != "_dmarc.example.com" {
					t.Fatalf("unexpected DNS query: %s", name)
				}
				return []string{tc.raw}, nil
			}
			if _, err := ParseRecord(tc.raw); err == nil {
				t.Fatal("strict record parser accepted invalid policy")
			}
			record, err := LookupRecord("example.com")
			if queries != 1 {
				t.Fatalf("DNS queries = %d, want 1", queries)
			}
			if !tc.wantNone {
				if err == nil || record != nil {
					t.Fatalf("invalid record unexpectedly accepted: %+v, %v", record, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupRecord() error = %v", err)
			}
			if record.Policy != PolicyNone || record.SubdomainPolicy != "" || record.Percent != 100 || record.AlignmentDKIM != AlignmentRelaxed || record.AlignmentSPF != AlignmentRelaxed || !reflect.DeepEqual(record.AggregateReportURI, []ReportURI{{URI: "mailto:r@example.net"}}) {
				t.Fatalf("fallback record = %+v", record)
			}
		})
	}
}

func TestRFC7489InvalidSubdomainPolicyFallback(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	var queries []string
	DefaultResolver = func(name string) ([]string, error) {
		queries = append(queries, name)
		if name == "_dmarc.mail.example.com" {
			return []string{"v=DMARC1; p=reject; sp=bad; rua=mailto:r@example.net"}, nil
		}
		return nil, errors.New("unexpected organizational-domain query")
	}
	record, err := LookupRecordWithSubdomainFallback("mail.example.com")
	if err != nil || record.EffectivePolicy() != PolicyNone || record.IsSubdomainPolicy || !reflect.DeepEqual(queries, []string{"_dmarc.mail.example.com"}) {
		t.Fatalf("record=%+v error=%v queries=%v", record, err, queries)
	}
}

func TestRFC7489LeadingWhitespaceDoesNotSelectDMARCRecord(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	DefaultResolver = func(string) ([]string, error) {
		return []string{" v=DMARC1; p=reject"}, nil
	}
	if record, err := LookupRecord("example.com"); !errors.Is(err, ErrNoRecordFound) || record != nil {
		t.Fatalf("LookupRecord() = %+v, %v; want no record", record, err)
	}
}

func TestRFC7489VersionWithControlDoesNotSelectDMARCRecord(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	DefaultResolver = func(string) ([]string, error) {
		return []string{"v=DMARC1\v; p=reject"}, nil
	}
	if record, err := LookupRecord("example.com"); !errors.Is(err, ErrNoRecordFound) || record != nil {
		t.Fatalf("LookupRecord() = %+v, %v; want no record", record, err)
	}
}

func TestRFC7489InvalidOptionalTagsDoNotDiscardPolicy(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	for _, tc := range []struct {
		name, raw string
		wantRua   int
		wantRuf   int
	}{
		{"invalid alignment", "v=DMARC1; p=reject; adkim=x; rua=mailto:r@example.net", 1, 0},
		{"invalid percentage", "v=DMARC1; p=reject; pct=101", 0, 0},
		{"invalid interval", "v=DMARC1; p=reject; ri=-1", 0, 0},
		{"invalid report URI", "v=DMARC1; p=reject; rua=mailto:bad space@example.net", 0, 0},
		{"invalid failure option", "v=DMARC1; p=reject; fo=x; ruf=mailto:r@example.net", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			DefaultResolver = func(string) ([]string, error) { return []string{tc.raw}, nil }
			record, err := LookupRecord("example.com")
			if err != nil || record.Policy != PolicyReject || record.AlignmentDKIM != AlignmentRelaxed || record.Percent != 100 || record.ReportInterval != 86400 || len(record.AggregateReportURI) != tc.wantRua || len(record.ForensicReportURI) != tc.wantRuf || !reflect.DeepEqual(record.FailureOptions, []FailureOption{FailureAllFail}) {
				t.Fatalf("LookupRecord() = %+v, %v", record, err)
			}
		})
	}
}

func TestRFC7489LookupRecoversAfterInvalidOptionalTag(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	DefaultResolver = func(string) ([]string, error) {
		return []string{"v=DMARC1; p=reject; pct=101; pct=40; fo=1; ruf=mailto:r@example.net"}, nil
	}
	record, err := LookupRecord("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if record.Policy != PolicyReject || record.Percent != 40 || !reflect.DeepEqual(record.FailureOptions, []FailureOption{FailureAnyFail}) {
		t.Fatalf("recovered optional tags = %+v", record)
	}
}
