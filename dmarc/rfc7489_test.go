package dmarc

import (
	"errors"
	"math"
	"net"
	"reflect"
	"testing"
)

func TestRFC7489RecordTagOrderAndUniqueness(t *testing.T) {
	for _, tc := range []struct {
		name, record string
		valid        bool
	}{
		{"valid policy", "v=DMARC1; p=reject; x-future=ignored", true},
		{"terminal separator", "v=DMARC1; p=reject;", true},
		{"consecutive separators", "v=DMARC1; p=reject;;", false},
		{"empty middle tag", "v=DMARC1; p=reject; ; pct=50", false},
		{"trailing control", "v=DMARC1; p=reject\v", false},
		{"embedded newline", "v=DMARC1; p=reject\n", false},
		{"non-WSP after policy", "v=DMARC1; p=reject\u00a0", false},
		{"leading whitespace", " v=DMARC1; p=reject", false},
		{"missing version", "p=reject", false},
		{"wrong version", "v=DMARC2; p=reject", false},
		{"version after policy", "p=reject; v=DMARC1", false},
		{"policy after optional tag", "v=DMARC1; pct=50; p=reject", false},
		{"missing policy", "v=DMARC1; pct=50", false},
		{"duplicate version", "v=DMARC1; p=none; v=DMARC1", false},
		{"duplicate policy", "v=DMARC1; p=none; p=reject", false},
		{"duplicate alignment", "v=DMARC1; p=none; adkim=r; adkim=s", false},
		{"duplicate percentage", "v=DMARC1; p=none; pct=0; pct=100", false},
		{"duplicate interval", "v=DMARC1; p=none; ri=1; ri=2", false},
		{"duplicate failure option", "v=DMARC1; p=none; fo=0; fo=1", false},
		{"duplicate report format", "v=DMARC1; p=none; rf=afrf; rf=afrf", false},
		{"duplicate subdomain policy", "v=DMARC1; p=none; sp=none; sp=reject", false},
		{"duplicate aggregate URI", "v=DMARC1; p=none; rua=mailto:a@example.com; rua=mailto:b@example.com", false},
		{"duplicate failure URI", "v=DMARC1; p=none; ruf=mailto:a@example.com; ruf=mailto:b@example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecord(tc.record)
			if (err == nil) != tc.valid {
				t.Fatalf("ParseRecord(%q) error=%v, valid=%v", tc.record, err, tc.valid)
			}
		})
	}
}

func TestRFC7489OptionalTagDefaultsValuesAndBounds(t *testing.T) {
	caseFolded, err := ParseRecord("v=DMARC1; P=REJECT; SP=Quarantine; ADKIM=S; ASPF=R; RUF=mailto:fail@example.com; FO=D:S; RF=AFRF")
	if err != nil || caseFolded.Policy != PolicyReject || caseFolded.SubdomainPolicy != PolicyQuarantine || caseFolded.AlignmentDKIM != AlignmentStrict || caseFolded.AlignmentSPF != AlignmentRelaxed || !reflect.DeepEqual(caseFolded.FailureOptions, []FailureOption{FailureDKIMOnly, FailureSPFOnly}) || !reflect.DeepEqual(caseFolded.ReportFormat, []ReportFormat{ReportFormatAFRF}) {
		t.Fatalf("case-insensitive ABNF values: record=%+v error=%v", caseFolded, err)
	}
	defaults, err := ParseRecord("v=DMARC1; p=none")
	if err != nil {
		t.Fatal(err)
	}
	if defaults.AlignmentDKIM != AlignmentRelaxed || defaults.AlignmentSPF != AlignmentRelaxed || defaults.Percent != 100 || defaults.ReportInterval != 86400 || !reflect.DeepEqual(defaults.FailureOptions, []FailureOption{FailureAllFail}) || !reflect.DeepEqual(defaults.ReportFormat, []ReportFormat{ReportFormatAFRF}) {
		t.Fatalf("incorrect defaults: %+v", defaults)
	}

	valid, err := ParseRecord("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=0; ri=4294967295; fo=1:d:s; rf=afrf; ruf=mailto:fail@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if valid.Policy != PolicyReject || valid.SubdomainPolicy != PolicyQuarantine || valid.AlignmentDKIM != AlignmentStrict || valid.AlignmentSPF != AlignmentStrict || valid.Percent != 0 || valid.ReportInterval != 4294967295 || !reflect.DeepEqual(valid.FailureOptions, []FailureOption{FailureAnyFail, FailureDKIMOnly, FailureSPFOnly}) || !reflect.DeepEqual(valid.ReportFormat, []ReportFormat{ReportFormatAFRF}) {
		t.Fatalf("explicit values not preserved: %+v", valid)
	}

	for _, tag := range []string{
		"adkim=x", "aspf=x", "pct=-1", "pct=101", "pct=+1", "pct=0000", "ri=-1", "ri=+1", "sp=invalid",
	} {
		t.Run(tag, func(t *testing.T) {
			_, err := ParseRecord("v=DMARC1; p=none; " + tag)
			if err == nil {
				t.Fatalf("invalid tag %q accepted", tag)
			}
		})
	}
	for _, fo := range []string{"fo=x", "fo=1:"} {
		t.Run(fo+" with ruf", func(t *testing.T) {
			if _, err := ParseRecord("v=DMARC1; p=none; ruf=mailto:failure@example.com; " + fo); err == nil {
				t.Fatalf("invalid failure option %q accepted with ruf", fo)
			}
		})
	}
	ignored, err := ParseRecord("v=DMARC1; p=none; fo=x")
	if err != nil || !reflect.DeepEqual(ignored.FailureOptions, []FailureOption{FailureAllFail}) {
		t.Fatalf("fo without ruf must be ignored: record=%+v, error=%v", ignored, err)
	}
	ignored, err = ParseRecord("v=DMARC1; p=none; fo=1")
	if err != nil || !reflect.DeepEqual(ignored.FailureOptions, []FailureOption{FailureAllFail}) {
		t.Fatalf("fo without ruf must use default: record=%+v, error=%v", ignored, err)
	}
	for _, value := range []string{"4294967296", "0004294967296", "184467440737095516160000"} {
		t.Run("large ri="+value, func(t *testing.T) {
			if record, err := ParseRecord("v=DMARC1; p=none; ri=" + value); err == nil {
				t.Fatalf("out-of-range ri=%s accepted: %+v", value, record)
			}
		})
	}
}

func TestRFC7489ReportURIListAndSizeBoundaries(t *testing.T) {
	r, err := ParseRecord("v=DMARC1; p=none; rua=mailto:a%2Cb@example.com!1k,mailto:b%21c@example.com!2m; ruf=mailto:forensic@example.com!3g,mailto:other@example.com!4t")
	if err != nil {
		t.Fatal(err)
	}
	wantRua := []ReportURI{{URI: "mailto:a%2Cb@example.com", MaxSize: 1 << 10, HasSize: true}, {URI: "mailto:b%21c@example.com", MaxSize: 2 << 20, HasSize: true}}
	wantRuf := []ReportURI{{URI: "mailto:forensic@example.com", MaxSize: 3 << 30, HasSize: true}, {URI: "mailto:other@example.com", MaxSize: 4 << 40, HasSize: true}}
	if !reflect.DeepEqual(r.AggregateReportURI, wantRua) || !reflect.DeepEqual(r.ForensicReportURI, wantRuf) {
		t.Fatalf("URI lists: rua=%+v, ruf=%+v", r.AggregateReportURI, r.ForensicReportURI)
	}
	withoutLimit, err := parseReportURI("mailto:reports@example.com")
	if err != nil {
		t.Fatal(err)
	}
	zeroLimit, err := parseReportURI("mailto:reports@example.com!0")
	if err != nil {
		t.Fatal(err)
	}
	if withoutLimit.HasSize || !zeroLimit.HasSize || zeroLimit.MaxSize != 0 {
		t.Fatalf("size absence and !0 collapsed: absent=%+v explicit=%+v", withoutLimit, zeroLimit)
	}
	for _, uri := range []string{
		"mailto:a@example.com!9223372036854775808",
		"mailto:a@example.com!18446744073709551615t",
		"mailto:a@example.com!8388608t",
	} {
		t.Run("large size "+uri, func(t *testing.T) {
			parsed, err := parseReportURI(uri)
			if err != nil || parsed.MaxSize != math.MaxInt64 || !parsed.HasSize {
				t.Fatalf("URI=%s: parsed=%+v, error=%v", uri, parsed, err)
			}
		})
	}
	for _, list := range []string{"rua=", "rua=mailto:a@example.com,", "rua=mailto:a@example.com,,mailto:b@example.com", "ruf=,mailto:a@example.com"} {
		t.Run(list, func(t *testing.T) {
			if _, err := ParseRecord("v=DMARC1; p=none; " + list); err == nil {
				t.Fatalf("invalid URI list %q accepted", list)
			}
		})
	}
	for _, uri := range []string{
		"relative/path", "mailto:bad%ZZ@example.com", "mailto:a b@example.com", "http://example.com/hi there", "mailto:a@example.com!", "mailto:a@example.com!1x", "mailto:a@example.com!18446744073709551616",
	} {
		t.Run(uri, func(t *testing.T) {
			if _, err := parseReportURI(uri); err == nil {
				t.Fatalf("invalid report URI %q accepted", uri)
			}
		})
	}
}

func TestRFC7489OrganizationalDomainLookupBoundary(t *testing.T) {
	old := DefaultResolver
	t.Cleanup(func() { DefaultResolver = old })
	for _, tc := range []struct {
		name, domain string
		records      map[string][]string
		wantQueries  []string
		wantPolicy   PolicyType
		wantFallback bool
		wantErr      error
	}{
		{"direct policy wins", "deep.shop.example.co.uk", map[string][]string{"_dmarc.deep.shop.example.co.uk": {"v=DMARC1; p=reject"}, "_dmarc.example.co.uk": {"v=DMARC1; p=none"}}, []string{"_dmarc.deep.shop.example.co.uk"}, PolicyReject, false, nil},
		{"fallback skips intermediate and public suffix", "deep.shop.example.co.uk", map[string][]string{"_dmarc.shop.example.co.uk": {"v=DMARC1; p=reject"}, "_dmarc.example.co.uk": {"v=DMARC1; p=none; sp=quarantine"}, "_dmarc.co.uk": {"v=DMARC1; p=reject"}}, []string{"_dmarc.deep.shop.example.co.uk", "_dmarc.example.co.uk"}, PolicyQuarantine, true, nil},
		{"other TXT and version discarded", "deep.shop.example.co.uk", map[string][]string{"_dmarc.deep.shop.example.co.uk": {"verification=ok", "v=DMARC2; p=reject"}, "_dmarc.example.co.uk": {"v=DMARC1; p=reject"}}, []string{"_dmarc.deep.shop.example.co.uk", "_dmarc.example.co.uk"}, PolicyReject, true, nil},
		{"no parent above private suffix", "tenant.github.io", map[string][]string{"_dmarc.github.io": {"v=DMARC1; p=reject"}}, []string{"_dmarc.tenant.github.io"}, "", false, ErrNoRecordFound},
		{"no third query after empty organization", "deep.shop.example.co.uk", map[string][]string{"_dmarc.co.uk": {"v=DMARC1; p=reject"}}, []string{"_dmarc.deep.shop.example.co.uk", "_dmarc.example.co.uk"}, "", false, ErrNoRecordFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries []string
			DefaultResolver = func(name string) ([]string, error) {
				queries = append(queries, name)
				if records, ok := tc.records[name]; ok {
					return records, nil
				}
				return nil, &net.DNSError{Name: name, IsNotFound: true}
			}
			r, err := LookupRecordWithSubdomainFallback(tc.domain)
			if !errors.Is(err, tc.wantErr) || !reflect.DeepEqual(queries, tc.wantQueries) {
				t.Fatalf("error=%v, queries=%v; want %v/%v", err, queries, tc.wantErr, tc.wantQueries)
			}
			if tc.wantErr == nil && (r == nil || r.EffectivePolicy() != tc.wantPolicy || r.IsSubdomainPolicy != tc.wantFallback) {
				t.Fatalf("record=%+v; want policy %s fallback %v", r, tc.wantPolicy, tc.wantFallback)
			}
		})
	}
}
