package dmarc

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// AuthenticatedDomain is a DKIM signing domain and its verification result.
// Only a passing signature can provide an aligned identifier.
type AuthenticatedDomain struct {
	Domain string
	Passed bool
}

// AlignmentResult records which underlying methods satisfy RFC 7489 §3.1.
type AlignmentResult struct {
	DKIMAligned bool
	SPFAligned  bool
	Pass        bool
}

// EvaluateAlignment compares the RFC5322.From domain with verified DKIM d=
// domains and the SPF MAIL FROM domain. For a null reverse-path, callers pass
// the synthesized MAIL FROM domain derived from HELO (RFC 7208 §2.4).
// This function evaluates alignment only; it does not discover or apply policy.
func EvaluateAlignment(record *Record, authorDomain string, dkim []AuthenticatedDomain, mailFromDomain string, spfPassed bool) (AlignmentResult, error) {
	var result AlignmentResult
	if record == nil {
		return result, fmt.Errorf("DMARC record is nil")
	}
	if !validAlignmentMode(record.AlignmentDKIM) || !validAlignmentMode(record.AlignmentSPF) {
		return result, fmt.Errorf("invalid DMARC alignment mode")
	}
	author, authorOrg, err := alignmentDomain(authorDomain)
	if err != nil {
		return result, fmt.Errorf("invalid RFC5322.From domain: %w", err)
	}
	for _, signature := range dkim {
		if signature.Passed && domainsAligned(author, authorOrg, signature.Domain, record.AlignmentDKIM) {
			result.DKIMAligned = true
			break
		}
	}
	if spfPassed {
		result.SPFAligned = domainsAligned(author, authorOrg, mailFromDomain, record.AlignmentSPF)
	}
	result.Pass = result.DKIMAligned || result.SPFAligned
	return result, nil
}

// NormalizeAuthorDomain converts an RFC5322.From domain to a lower-case DNS
// A-label for DMARC policy discovery (RFC 7489 §6.6.1).
func NormalizeAuthorDomain(domain string) (string, error) {
	ascii, _, err := alignmentDomain(domain)
	return ascii, err
}

func validAlignmentMode(mode AlignmentMode) bool {
	return mode == "" || mode == AlignmentRelaxed || mode == AlignmentStrict
}

func domainsAligned(author, authorOrg, authenticated string, mode AlignmentMode) bool {
	domain, org, err := alignmentDomain(authenticated)
	if err != nil {
		return false
	}
	if mode == AlignmentStrict {
		return author == domain
	}
	return authorOrg == org
}

func alignmentDomain(domain string) (string, string, error) {
	domain = strings.TrimSuffix(domain, ".")
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", "", err
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", "", fmt.Errorf("invalid DNS name")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", "", fmt.Errorf("invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				continue
			}
			if c != '-' || i == 0 || i == len(label)-1 {
				return "", "", fmt.Errorf("invalid DNS label")
			}
		}
	}
	org, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return "", "", err
	}
	return ascii, org, nil
}
