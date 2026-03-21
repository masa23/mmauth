package dmarc

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type TXTLookupFunc func(name string) ([]string, error)

// DefaultResolver is the default TXT lookup function.
var DefaultResolver TXTLookupFunc = net.LookupTXT

var (
	ErrNoRecordFound   = errors.New("no record found")
	ErrDNSLookupFailed = errors.New("dns lookup failed")
)

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
	MaxSize int64  // Maximum size in bytes (0 means no limit)
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
	isSubdomainPolicy  bool            // isSubdomainPolicy true if this is a subdomain policy
	raw                string          // raw record
}

// parseReportURI parses a DMARC URI with optional size limit.
// Format: URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]
// Example: "mailto:reports@example.com!50m" -> 50 * 2^20 bytes
// Per RFC 7489 Section 6.2 and 6.4.
// Note: While '!' is a valid character in generic URIs (RFC 3986),
// DMARC report URIs typically use mailto: or http/https schemes where '!' in the
// URI portion is uncommon. For safety, we treat any size spec after the last '!'
// that matches the pattern; if it doesn't match, we reject it to avoid silent errors.
func parseReportURI(uri string) (*ReportURI, error) {
	// Check if URI contains only size specification (URI part is empty)
	if strings.HasPrefix(uri, "!") {
		return nil, fmt.Errorf("invalid report URI: %s (URI cannot start with '!')", uri)
	}

	// Find the last '!' which would separate URI from size limit
	lastExclamation := strings.LastIndex(uri, "!")

	var uriPart string
	var sizeSpec string

	if lastExclamation != -1 {
		// Check if there are multiple '!' characters (which would be ambiguous)
		if strings.Index(uri, "!") != lastExclamation {
			// Multiple '!' characters found - this is ambiguous and should be rejected
			// since we can't determine which one is the actual size delimiter
			return nil, fmt.Errorf("invalid report URI: %s (multiple '!' delimiters are not allowed)", uri)
		}

		sizeSpec = strings.TrimSpace(uri[lastExclamation+1:])
		uriPart = uri[:lastExclamation]
	} else {
		uriPart = uri
		sizeSpec = ""
	}

	result := &ReportURI{
		URI:     strings.TrimSpace(uriPart),
		MaxSize: 0, // No limit by default
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

		// Apply unit multiplier (powers of two per RFC 7489)
		// Use uint64 for the shift operation to avoid overflow before final int64 conversion
		// Pre-check for overflow before shifting
		var maxSize uint64
		switch strings.ToLower(unit) {
		case "":
			maxSize = num
		case "k":
			if num > (uint64(math.MaxInt64) >> 10) {
				return nil, fmt.Errorf("size limit too large in URI: %s (max %d bytes)", uri, math.MaxInt64)
			}
			maxSize = num << 10 // 2^10
		case "m":
			if num > (uint64(math.MaxInt64) >> 20) {
				return nil, fmt.Errorf("size limit too large in URI: %s (max %d bytes)", uri, math.MaxInt64)
			}
			maxSize = num << 20 // 2^20
		case "g":
			if num > (uint64(math.MaxInt64) >> 30) {
				return nil, fmt.Errorf("size limit too large in URI: %s (max %d bytes)", uri, math.MaxInt64)
			}
			maxSize = num << 30 // 2^30
		case "t":
			if num > (uint64(math.MaxInt64) >> 40) {
				return nil, fmt.Errorf("size limit too large in URI: %s (max %d bytes)", uri, math.MaxInt64)
			}
			maxSize = num << 40 // 2^40
		default:
			return nil, fmt.Errorf("invalid size unit in URI: %s (must be k/m/g/t)", uri)
		}

		// Final check (redundant but kept as safety net)
		if maxSize > math.MaxInt64 {
			return nil, fmt.Errorf("size limit too large in URI: %s (max %d bytes)", uri, math.MaxInt64)
		}
		result.MaxSize = int64(maxSize)
	}

	if result.URI == "" {
		return nil, fmt.Errorf("empty URI in report URI: %s", uri)
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

func LookupRecordWithSubdomainFallback(domain string) (*Record, error) {
	d, err := LookupRecord(domain)
	if err == nil {
		return d, nil
	}
	for {
		orgDomain, err := getParentDomain(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get organizational domain: %w", err)
		}
		if orgDomain == domain {
			return nil, ErrNoRecordFound
		}
		d, err = LookupRecord(orgDomain)
		if err == nil {
			if d.SubdomainPolicy == "" {
				return nil, ErrNoRecordFound
			}
			d.isSubdomainPolicy = true
			return d, nil
		}
		domain = orgDomain
		if errors.Is(err, ErrNoRecordFound) {
			continue
		}
		return nil, err
	}
}

func LookupRecord(domain string) (*Record, error) {
	query := fmt.Sprintf("_dmarc.%s", domain)
	res, err := DefaultResolver(query)
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsNotFound {
			return nil, ErrNoRecordFound
		}
	} else if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}
	for _, v := range res {
		d, err := ParseRecord(v)
		if err != nil {
			return nil, err
		}
		if d.Policy != "" {
			return d, nil
		}
	}
	return nil, ErrNoRecordFound
}

func ParseRecord(raw string) (*Record, error) {
	var d Record
	d.raw = raw

	// Track whether rua/ruf tags have been seen to properly detect duplicates
	// even when the tag parsing fails to add any valid URIs
	var sawRuaTag bool
	var sawRufTag bool

	pairs := strings.Split(raw, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid tag format: %s", pair)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "v":
			d.Version = strings.TrimSpace(v)
			if d.Version != "DMARC1" {
				return nil, fmt.Errorf("invalid version: %s", d.Version)
			}
		case "rua":
			// Reject duplicate rua tags for deterministic behavior
			if sawRuaTag {
				return nil, fmt.Errorf("duplicate 'rua' tag in DMARC record")
			}
			sawRuaTag = true
			rawURIs := strings.Split(strings.TrimSpace(v), ",")
			for _, uri := range rawURIs {
				uri = strings.TrimSpace(uri)
				if uri == "" {
					continue
				}
				parsed, err := parseReportURI(uri)
				if err != nil {
					return nil, fmt.Errorf("invalid rua URI: %w", err)
				}
				d.AggregateReportURI = append(d.AggregateReportURI, *parsed)
			}
		case "adkim":
			d.AlignmentDKIM = AlignmentMode(strings.TrimSpace(v))
			if d.AlignmentDKIM != AlignmentRelaxed && d.AlignmentDKIM != AlignmentStrict {
				return nil, fmt.Errorf("invalid adkim value: %s", d.AlignmentDKIM)
			}
		case "aspf":
			d.AlignmentSPF = AlignmentMode(strings.TrimSpace(v))
			if d.AlignmentSPF != AlignmentRelaxed && d.AlignmentSPF != AlignmentStrict {
				return nil, fmt.Errorf("invalid aspf value: %s", d.AlignmentSPF)
			}
		case "ruf":
			// Reject duplicate ruf tags for deterministic behavior
			if sawRufTag {
				return nil, fmt.Errorf("duplicate 'ruf' tag in DMARC record")
			}
			sawRufTag = true
			rawURIs := strings.Split(strings.TrimSpace(v), ",")
			for _, uri := range rawURIs {
				uri = strings.TrimSpace(uri)
				if uri == "" {
					continue
				}
				parsed, err := parseReportURI(uri)
				if err != nil {
					return nil, fmt.Errorf("invalid ruf URI: %w", err)
				}
				d.ForensicReportURI = append(d.ForensicReportURI, *parsed)
			}
		case "fo":
			fo := strings.Split(strings.TrimSpace(v), ":")
			for _, f := range fo {
				switch FailureOption(f) {
				case FailureAllFail, FailureAnyFail, FailureDKIMOnly, FailureSPFOnly:
					d.FailureOptions = append(d.FailureOptions, FailureOption(f))
				default:
					return nil, fmt.Errorf("invalid fo value: %s", f)
				}
			}
		case "pct":
			pct, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("invalid pct value: %s", v)
			}
			if pct < 0 || pct > 100 {
				return nil, fmt.Errorf("pct value out of range: %d", pct)
			}
			d.Percent = pct
		case "p":
			d.Policy = PolicyType(strings.TrimSpace(v))
			if d.Policy != PolicyNone && d.Policy != PolicyQuarantine && d.Policy != PolicyReject {
				return nil, fmt.Errorf("invalid p value: %s", d.Policy)
			}
		case "rf":
			// rf: Format for message-specific failure reports
			// Per RFC 7489 Section 6.3.8, only "afrf" is currently supported
			formats := strings.Split(strings.TrimSpace(v), ":")
			seenFormats := make(map[string]bool) // Track seen formats to prevent duplicates
			for _, format := range formats {
				format = strings.TrimSpace(format)
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
			ri, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("invalid ri value: %s", v)
			}
			if ri < 0 {
				return nil, fmt.Errorf("ri value out of range: %d", ri)
			}
			d.ReportInterval = uint32(ri)
		case "sp":
			d.SubdomainPolicy = PolicyType(strings.TrimSpace(v))
			if d.SubdomainPolicy != PolicyNone && d.SubdomainPolicy != PolicyQuarantine && d.SubdomainPolicy != PolicyReject {
				return nil, fmt.Errorf("invalid sp value: %s", d.SubdomainPolicy)
			}
		}
	}

	// Validate required fields per RFC 7489 Section 6.3
	if d.Version == "" {
		return nil, fmt.Errorf("missing version tag in DMARC record")
	}
	// p tag is REQUIRED for policy records per RFC 7489 Section 6.3.7
	if d.Policy == "" {
		return nil, fmt.Errorf("missing required 'p' tag in DMARC record")
	}

	return &d, nil
}
