package dmarc

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type TXTLookupFunc func(name string) ([]string, error)

// DefaultResolver is the default TXT lookup function.
var DefaultResolver TXTLookupFunc = net.LookupTXT

var (
	ErrNoRecordFound    = errors.New("no record found")
	ErrDNSLookupFailed  = errors.New("dns lookup failed")
	ErrMultipleRecords  = errors.New("multiple DMARC records found")
	errInvalidPolicyTag = errors.New("invalid DMARC policy tag")
)

type invalidPolicyTagError string

func (e invalidPolicyTagError) Error() string        { return string(e) }
func (e invalidPolicyTagError) Is(target error) bool { return target == errInvalidPolicyTag }

// dnsLookupError preserves the resolver error and supports errors.Is with the
// package sentinel, including on Go 1.19 (which predates multiple %w values).
type dnsLookupError struct{ cause error }

func (e *dnsLookupError) Error() string        { return ErrDNSLookupFailed.Error() + ": " + e.cause.Error() }
func (e *dnsLookupError) Unwrap() error        { return e.cause }
func (e *dnsLookupError) Is(target error) bool { return target == ErrDNSLookupFailed }

type AlignmentMode string

const (
	AlignmentRelaxed AlignmentMode = "r" // relaxed
	AlignmentStrict  AlignmentMode = "s" // strict
)

type FailureOption string

const (
	FailureAllFail  FailureOption = "0" // Report when all mechanisms fail with no aligned pass
	FailureAnyFail  FailureOption = "1" // Report when any mechanism fails to produce aligned pass
	FailureDKIMOnly FailureOption = "d" // Report when a DKIM signature fails evaluation
	FailureSPFOnly  FailureOption = "s" // Report when SPF evaluation fails
)

type PolicyType string

const (
	PolicyNone       PolicyType = "none"
	PolicyQuarantine PolicyType = "quarantine"
	PolicyReject     PolicyType = "reject"
)

// ReportFormat represents the format requested for message-specific failure reports.
// Per RFC 7489 Section 6.3.8, only "afrf" is currently supported.
type ReportFormat string

const (
	ReportFormatAFRF ReportFormat = "afrf" // Authentication Failure Reporting Format
)

// ReportURI represents a DMARC URI with an optional size limit.
// Example: "mailto:reports@example.com!50m" (50 megabytes max)
// Per RFC 7489 Section 6.2 and 6.4.
type ReportURI struct {
	URI     string // The report URI
	MaxSize int64  // Maximum size in bytes, capped at MaxInt64 (0 when absent or explicitly zero)
	HasSize bool   // Whether the URI included an explicit size limit, including !0
}

type Record struct {
	AggregateReportURI []ReportURI     // rua Aggregate report URIs
	AlignmentDKIM      AlignmentMode   // adkim DKIM alignment mode (r or s)
	AlignmentSPF       AlignmentMode   // aspf SPF alignment mode (r or s)
	ForensicReportURI  []ReportURI     // ruf Forensic report URIs (optional, deprecated)
	FailureOptions     []FailureOption // fo Forensic reporting options (optional, deprecated)
	Percent            int             // pct Percentage of messages to apply policy to
	Policy             PolicyType      // p Policy (none, quarantine, reject)
	ReportFormat       []ReportFormat  // rf Format for message-specific failure reports
	ReportInterval     uint32          // ri Interval for aggregate reports (seconds)
	SubdomainPolicy    PolicyType      // sp Subdomain policy
	Version            string          // v DMARC version, must be "DMARC1"
	// IsSubdomainPolicy records whether lookup fell back to the organizational
	// domain. Preserve it when caching records so EffectivePolicy still uses sp.
	IsSubdomainPolicy bool   `json:",omitempty"`
	raw               string // raw record
}

// parseReportURI parses a DMARC URI with optional size limit.
// Format: URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]
// Example: "mailto:reports@example.com!50m" -> 50 * 2^20 bytes
// Per RFC 7489 Section 6.2 and 6.4.
// Note: Multiple '!' characters are not allowed to avoid ambiguity in parsing.
// If '!' is present, it is treated as the size delimiter and must be followed
// by a valid size specification.
func parseReportURI(uri string) (*ReportURI, error) {
	// Check if URI contains only size specification (URI part is empty)
	if strings.HasPrefix(uri, "!") {
		return nil, fmt.Errorf("invalid report URI: %s (URI cannot start with '!')", uri)
	}

	// Find the '!' delimiter which separates URI from size limit
	// Multiple '!' delimiters are not allowed
	lastExclamation := strings.LastIndex(uri, "!")

	var uriPart string
	var sizeSpec string

	if lastExclamation != -1 {
		// Check if there are multiple '!' characters
		// Multiple '!' delimiters are not allowed as they would be ambiguous
		if strings.Index(uri, "!") != lastExclamation {
			return nil, fmt.Errorf("invalid report URI: %s (multiple '!' delimiters are not allowed)", uri)
		}

		sizeSpec = trimWSP(uri[lastExclamation+1:])
		uriPart = uri[:lastExclamation]

		// If a '!' delimiter was present, the post-'!' portion must not be empty/whitespace
		if sizeSpec == "" {
			return nil, fmt.Errorf("invalid report URI: %s (missing size limit after '!')", uri)
		}
	} else {
		uriPart = uri
		sizeSpec = ""
	}

	result := &ReportURI{
		URI:     trimWSP(uriPart),
		MaxSize: 0,
		HasSize: lastExclamation != -1,
	}

	// Parse size limit if present
	if sizeSpec != "" {
		// Extract numeric part and unit without incremental concatenation
		var numStr string
		var unit string
		i := 0
		for i < len(sizeSpec) && sizeSpec[i] >= '0' && sizeSpec[i] <= '9' {
			i++
		}
		numStr = sizeSpec[:i]
		unit = sizeSpec[i:]

		// Validate that we have at least one digit and a valid unit (if present)
		if len(numStr) == 0 {
			return nil, fmt.Errorf("invalid size specification in URI: %s (must start with digits)", uri)
		}

		// Parse the numeric value
		num, err := strconv.ParseUint(numStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid size number in URI: %s", uri)
		}

		// The RFC bounds the numeric portion to uint64, but multiplication
		// by a unit can exceed the public int64 field. Saturate that field
		// instead of rejecting an otherwise valid record.
		var shift uint
		switch strings.ToLower(unit) {
		case "":
			shift = 0
		case "k":
			shift = 10
		case "m":
			shift = 20
		case "g":
			shift = 30
		case "t":
			shift = 40
		default:
			return nil, fmt.Errorf("invalid size unit in URI: %s (must be k/m/g/t)", uri)
		}
		if num > uint64(math.MaxInt64)>>shift {
			result.MaxSize = math.MaxInt64
		} else {
			result.MaxSize = int64(num << shift)
		}
	}

	if result.URI == "" {
		return nil, fmt.Errorf("empty URI in report URI: %s", uri)
	}
	// RFC 7489 imports RFC 3986 URI syntax. net/url accepts raw spaces and
	// other characters that RFC 3986 requires to be percent-encoded.
	for i := 0; i < len(result.URI); i++ {
		c := result.URI[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.ContainsRune("-._~:/?#[]@!$&'()*+,;=%", rune(c)) {
			continue
		}
		return nil, fmt.Errorf("invalid report URI character: %s", uri)
	}
	parsedURI, err := url.Parse(result.URI)
	if err != nil || parsedURI.Scheme == "" {
		return nil, fmt.Errorf("invalid report URI: %s", uri)
	}
	if _, err := url.PathUnescape(result.URI); err != nil {
		return nil, fmt.Errorf("invalid report URI escape: %s", uri)
	}

	return result, nil
}

func getParentDomain(domain string) (string, error) {
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", fmt.Errorf("failed to get organizational domain: %w", err)
	}
	if orgDomain == domain {
		return domain, nil
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	parentDomain := strings.Join(parts[1:], ".")
	return parentDomain, nil
}

// LookupRecordWithSubdomainFallback queries the From domain, then its
// organizational domain directly (RFC 7489 §6.6.3).
func LookupRecordWithSubdomainFallback(domain string) (*Record, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	d, err := LookupRecord(domain)
	if !errors.Is(err, ErrNoRecordFound) {
		return d, err
	}
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get organizational domain: %w", err)
	}
	if orgDomain == domain {
		return nil, ErrNoRecordFound
	}
	d, err = LookupRecord(orgDomain)
	if err != nil {
		return nil, err
	}
	if d.SubdomainPolicy == "" {
		d.SubdomainPolicy = d.Policy
	}
	d.IsSubdomainPolicy = true
	return d, nil
}

// EffectivePolicy returns the policy for the domain used in the lookup.
func (d *Record) EffectivePolicy() PolicyType {
	if d.IsSubdomainPolicy && d.SubdomainPolicy != "" {
		return d.SubdomainPolicy
	}
	return d.Policy
}

func isDMARCRecord(raw string) bool {
	firstTag, _, _ := strings.Cut(raw, ";")
	if raw == "" || (raw[0] != 'v' && raw[0] != 'V') {
		return false
	}
	key, value, ok := strings.Cut(firstTag, "=")
	if !ok {
		return false
	}
	return strings.EqualFold(strings.Trim(key, " \t"), "v") && strings.Trim(value, " \t") == "DMARC1"
}

func LookupRecord(domain string) (*Record, error) {
	query := fmt.Sprintf("_dmarc.%s", domain)
	res, err := DefaultResolver(query)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, ErrNoRecordFound
		}
		return nil, &dnsLookupError{cause: err}
	}
	var dmarcRecords []string
	for _, v := range res {
		if isDMARCRecord(v) {
			dmarcRecords = append(dmarcRecords, v)
		}
	}
	if len(dmarcRecords) > 1 {
		return nil, ErrMultipleRecords
	}
	for _, v := range dmarcRecords {
		d, err := parseRecordForLookup(v)
		if err != nil {
			return nil, err
		}
		if d.Policy != "" {
			return d, nil
		}
	}
	return nil, ErrNoRecordFound
}

// RFC 7489 §6.3 permits policy discovery to ignore malformed optional tags.
// Both entry points use the same tag parser and defaults.
func parseRecordForLookup(raw string) (*Record, error) { return parseRecord(raw, true) }

func ParseRecord(raw string) (*Record, error) { return parseRecord(raw, false) }

func defaultRecord(raw string) Record {
	return Record{
		raw: raw, Percent: 100, AlignmentDKIM: AlignmentRelaxed,
		AlignmentSPF: AlignmentRelaxed, ReportInterval: 86400,
		FailureOptions: []FailureOption{FailureAllFail},
		ReportFormat:   []ReportFormat{ReportFormatAFRF},
	}
}

func recordTagKnown(tag string) bool {
	switch tag {
	case "v", "p", "sp", "rua", "ruf", "adkim", "aspf", "ri", "fo", "rf", "pct":
		return true
	}
	return false
}

func parseRecord(raw string, lookup bool) (*Record, error) {
	if raw == "" || (raw[0] != 'v' && raw[0] != 'V') {
		return nil, fmt.Errorf("version tag must be first")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < ' ' && raw[i] != '\t' || raw[i] == 127 {
			return nil, fmt.Errorf("invalid DMARC record control character")
		}
	}
	d := defaultRecord(raw)
	seen := make(map[string]bool)
	tagIndex := 0
	var foValue string
	var policyErr error
	var reportURIs []ReportURI
	pairs := strings.Split(raw, ";")
	for i, pair := range pairs {
		pair = trimWSP(pair)
		// RFC 7489 §6.4 tag values are ASCII. During discovery, ignore a
		// malformed optional tag as §6.3 recommends, but reject malformed
		// mandatory tags and strict ParseRecord input.
		invalidASCII := false
		for j := 0; j < len(pair); j++ {
			if pair[j] > '~' {
				invalidASCII = true
				break
			}
		}
		if invalidASCII {
			if !lookup || tagIndex < 2 {
				return nil, fmt.Errorf("invalid DMARC record character")
			}
			continue
		}
		if pair == "" {
			if !lookup && (i == 0 || i != len(pairs)-1) {
				return nil, fmt.Errorf("empty tag in DMARC record")
			}
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			if lookup && tagIndex >= 2 {
				continue
			}
			return nil, fmt.Errorf("invalid tag format: %s", pair)
		}
		tag := strings.ToLower(trimWSP(key))
		if lookup && tag == "rua" {
			// A bad p/sp can still yield reporting-only policy when one URI is valid.
			for _, candidate := range strings.Split(value, ",") {
				if uri, err := parseReportURI(trimWSP(candidate)); err == nil {
					reportURIs = append(reportURIs, *uri)
				}
			}
		}
		if tagIndex == 0 && tag != "v" {
			return nil, fmt.Errorf("version tag must be first")
		}
		if tagIndex == 1 && tag != "p" {
			err := invalidPolicyTagError("policy tag must follow version")
			if !lookup {
				return nil, err
			}
			policyErr = err
			tagIndex++
			continue
		}
		tagIndex++
		known := recordTagKnown(tag)
		if known && seen[tag] {
			if tag == "p" || tag == "sp" {
				err := invalidPolicyTagError(fmt.Sprintf("duplicate %q tag in DMARC record", tag))
				if !lookup {
					return nil, err
				}
				policyErr = err
			} else if !lookup {
				return nil, fmt.Errorf("duplicate %q tag in DMARC record", tag)
			}
			continue
		}
		next := d
		if err := applyRecordTag(&next, tag, value, &foValue); err != nil {
			if !lookup || tag == "v" {
				return nil, err
			}
			if errors.Is(err, errInvalidPolicyTag) {
				policyErr = err
				continue
			}
			if tagIndex <= 2 {
				return nil, err
			}
			continue
		}
		d = next
		if known {
			seen[tag] = true
		}
	}
	if d.Version == "" {
		return nil, fmt.Errorf("missing version tag in DMARC record")
	}
	if d.Policy == "" && policyErr == nil {
		policyErr = invalidPolicyTagError("missing required 'p' tag in DMARC record")
	}
	if policyErr != nil {
		if lookup && len(reportURIs) > 0 {
			fallback := defaultRecord(raw)
			fallback.Version = "DMARC1"
			fallback.Policy = PolicyNone
			fallback.AggregateReportURI = reportURIs
			return &fallback, nil
		}
		return nil, policyErr
	}
	if err := finishRecord(&d, seen["fo"], foValue); err != nil && !lookup {
		return nil, err
	}
	return &d, nil
}

func applyRecordTag(d *Record, tag, v string, foValue *string) error {
	switch tag {
	case "v":
		d.Version = trimWSP(v)
		if d.Version != "DMARC1" {
			return fmt.Errorf("invalid version: %s", d.Version)
		}
	case "rua":
		rawURIs := strings.Split(trimWSP(v), ",")
		for _, uri := range rawURIs {
			uri = trimWSP(uri)
			if uri == "" {
				return fmt.Errorf("empty rua URI")
			}
			parsed, err := parseReportURI(uri)
			if err != nil {
				return fmt.Errorf("invalid rua URI: %w", err)
			}
			d.AggregateReportURI = append(d.AggregateReportURI, *parsed)
		}
	case "adkim":
		d.AlignmentDKIM = AlignmentMode(strings.ToLower(trimWSP(v)))
		if d.AlignmentDKIM != AlignmentRelaxed && d.AlignmentDKIM != AlignmentStrict {
			return fmt.Errorf("invalid adkim value: %s", d.AlignmentDKIM)
		}
	case "aspf":
		d.AlignmentSPF = AlignmentMode(strings.ToLower(trimWSP(v)))
		if d.AlignmentSPF != AlignmentRelaxed && d.AlignmentSPF != AlignmentStrict {
			return fmt.Errorf("invalid aspf value: %s", d.AlignmentSPF)
		}
	case "ruf":
		rawURIs := strings.Split(trimWSP(v), ",")
		for _, uri := range rawURIs {
			uri = trimWSP(uri)
			if uri == "" {
				return fmt.Errorf("empty ruf URI")
			}
			parsed, err := parseReportURI(uri)
			if err != nil {
				return fmt.Errorf("invalid ruf URI: %w", err)
			}
			d.ForensicReportURI = append(d.ForensicReportURI, *parsed)
		}
	case "fo":
		*foValue = trimWSP(v)
	case "pct":
		value := trimWSP(v)
		if !isDecimalDigits(value) || len(value) > 3 {
			return fmt.Errorf("invalid pct value: %s", v)
		}
		pct, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid pct value: %s", v)
		}
		if pct < 0 || pct > 100 {
			return fmt.Errorf("pct value out of range: %d", pct)
		}
		d.Percent = pct
	case "p":
		d.Policy = PolicyType(strings.ToLower(trimWSP(v)))
		if d.Policy != PolicyNone && d.Policy != PolicyQuarantine && d.Policy != PolicyReject {
			return invalidPolicyTagError(fmt.Sprintf("invalid p value: %s", d.Policy))
		}
	case "rf":
		d.ReportFormat = nil
		// rf: Format for message-specific failure reports
		// Per RFC 7489 Section 6.3.8, only "afrf" is currently supported
		formats := strings.Split(trimWSP(v), ":")
		seenFormats := make(map[string]bool) // Track seen formats to prevent duplicates
		for _, format := range formats {
			format = strings.ToLower(trimWSP(format))
			if format == "" {
				continue
			}
			// Skip duplicates - values like "rf=afrf:afrf" should only produce one entry
			if seenFormats[format] {
				continue
			}
			seenFormats[format] = true
			// Currently only "afrf" is supported - other values should be ignored
			// per RFC 7489 Section 6.3.8
			if ReportFormat(format) == ReportFormatAFRF {
				d.ReportFormat = append(d.ReportFormat, ReportFormatAFRF)
			}
			// Unknown formats are silently ignored per RFC 7489 Section 6.3:
			// "A Mail Receiver observing a different value SHOULD ignore it or MAY ignore the entire DMARC record"
		}
	case "ri":
		value := trimWSP(v)
		if !isDecimalDigits(value) {
			return fmt.Errorf("invalid ri value: %s", v)
		}
		// RFC 7489 Section 6.3 limits ri to a 32-bit unsigned integer.
		normalized := strings.TrimLeft(value, "0")
		if normalized == "" {
			normalized = "0"
		}
		if len(normalized) > 10 || (len(normalized) == 10 && normalized > "4294967295") {
			return fmt.Errorf("ri value out of range: %s", v)
		}
		ri, err := strconv.ParseUint(normalized, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid ri value: %s", v)
		}
		d.ReportInterval = uint32(ri)
	case "sp":
		d.SubdomainPolicy = PolicyType(strings.ToLower(trimWSP(v)))
		if d.SubdomainPolicy != PolicyNone && d.SubdomainPolicy != PolicyQuarantine && d.SubdomainPolicy != PolicyReject {
			return invalidPolicyTagError(fmt.Sprintf("invalid sp value: %s", d.SubdomainPolicy))
		}
	}
	return nil
}

func finishRecord(d *Record, foSeen bool, foValue string) error {
	// RFC 7489 §6.3 ignores fo without a valid ruf URI.
	if len(d.ForensicReportURI) == 0 || !foSeen {
		return nil
	}
	var options []FailureOption
	for _, f := range strings.Split(foValue, ":") {
		f = strings.ToLower(trimWSP(f))
		switch FailureOption(f) {
		case FailureAllFail, FailureAnyFail, FailureDKIMOnly, FailureSPFOnly:
			options = append(options, FailureOption(f))
		default:
			return fmt.Errorf("invalid fo value: %s", f)
		}
	}
	d.FailureOptions = options
	return nil
}

func isDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimWSP(s string) string { return strings.Trim(s, " \t") }
