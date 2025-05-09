package dmarc

import (
	"errors"
	"fmt"
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

type Record struct {
	AggregateReportURI []string        // rua Aggregate report URIs
	AlignmentDKIM      AlignmentMode   // adkim DKIM alignment mode (r or s)
	AlignmentSPF       AlignmentMode   // aspf SPF alignment mode (r or s)
	ForensicReportURI  []string        // ruf Forensic report URIs (optional, deprecated)
	FailureOptions     []FailureOption // fo Forensic reporting options (optional, deprecated)
	Percent            int             // pct Percentage of messages to apply policy to
	Policy             PolicyType      // p Policy (none, quarantine, reject)
	ReportInterval     uint32          // ri Interval for aggregate reports (seconds)
	SubdomainPolicy    PolicyType      // sp Subdomain policy
	Version            string          // v DMARC version, must be "DMARC1"
	isSubdomainPolicy  bool            // isSubdomainPolicy true if this is a subdomain policy
	raw                string          // raw record
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
		switch strings.TrimSpace(k) {
		case "v":
			d.Version = strings.TrimSpace(v)
			if d.Version != "DMARC1" {
				return nil, fmt.Errorf("invalid version: %s", d.Version)
			}
		case "rua":
			rawURIs := strings.Split(strings.TrimSpace(v), ",")
			for i, uri := range rawURIs {
				rawURIs[i] = strings.TrimSpace(uri)
			}
			d.AggregateReportURI = rawURIs
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
			rawURIs := strings.Split(strings.TrimSpace(v), ",")
			for i, uri := range rawURIs {
				rawURIs[i] = strings.TrimSpace(uri)
			}
			d.ForensicReportURI = rawURIs
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

	if d.Version == "" {
		return nil, fmt.Errorf("missing version tag in DMARC record")
	}

	return &d, nil
}
