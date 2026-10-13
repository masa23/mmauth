package mmauth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"strings"

	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/dmarc"
	"github.com/masa23/mmauth/internal/header"
	"github.com/masa23/mmauth/spf"
)

// EvaluateDMARC verifies the message's DKIM signatures, checks SPF for the
// envelope identity, discovers the From domain policy, and evaluates the
// message under RFC 7489. It requires a completed MMAuth message (Close).
// Disposition is a recommendation; the receiving MTA makes the final choice.
func (m *MMAuth) EvaluateDMARC(remoteAddr net.IP, helo, mailFrom string) (dmarc.Evaluation, error) {
	var result dmarc.Evaluation
	if m == nil || !m.pclose || m.err != nil {
		return result, fmt.Errorf("message processing is incomplete")
	}
	authors, err := authorDomainsFromHeaders(m.Headers)
	if err != nil {
		return result, err
	}
	type authorPolicy struct {
		domain string
		record *dmarc.Record
	}
	var policies []authorPolicy
	seenCanonical := make(map[string]bool, len(authors))
	for _, author := range authors {
		canonical, normalizeErr := dmarc.NormalizeAuthorDomain(author)
		if normalizeErr != nil {
			return result, fmt.Errorf("invalid RFC5322.From domain: %w", normalizeErr)
		}
		if seenCanonical[canonical] {
			continue
		}
		seenCanonical[canonical] = true
		record, lookupErr := dmarc.LookupRecordWithSubdomainFallback(canonical)
		if errors.Is(lookupErr, dmarc.ErrNoRecordFound) {
			continue
		}
		if lookupErr != nil {
			status := dmarc.EvaluationNone
			if errors.Is(lookupErr, dmarc.ErrDNSLookupFailed) {
				status = dmarc.EvaluationTempError
			}
			return dmarc.Evaluation{Status: status, Disposition: dmarc.PolicyNone}, lookupErr
		}
		policies = append(policies, authorPolicy{canonical, record})
	}
	if len(policies) == 0 {
		return dmarc.Evaluation{Status: dmarc.EvaluationNone, Disposition: dmarc.PolicyNone}, nil
	}
	if m.AuthenticationHeaders == nil {
		return result, fmt.Errorf("authentication headers are unavailable")
	}
	// Verification is idempotent for the result but can repeat DNS queries, so
	// only verify signatures whose result has not yet been populated.
	var signatures []dmarc.DKIMIdentity
	if m.AuthenticationHeaders.DKIMSignatures != nil {
		for _, signature := range *m.AuthenticationHeaders.DKIMSignatures {
			if signature == nil {
				continue
			}
			if signature.VerifyResult == nil {
				can := signature.GetCanonicalizationAndAlgorithm()
				if can != nil {
					bodyHash := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{
						Body: Canonicalization(can.Body), Algorithm: can.HashAlgo,
						Limit: signature.Limit, LimitSet: signature.LimitSet,
					})
					signature.Verify(m.Headers, bodyHash, nil)
				}
			}
			identity := dmarc.DKIMIdentity{Domain: signature.Domain}
			if signature.VerifyResult != nil {
				identity.Passed = signature.VerifyResult.Status() == dkim.VerifyStatusPass
				identity.TemporaryError = signature.VerifyResult.Status() == dkim.VerifyStatusTempErr
			}
			signatures = append(signatures, identity)
		}
	}
	spfResult, spfDomain := evaluateSPFIdentity(remoteAddr, helo, mailFrom)
	m.AuthenticationHeaders.SPFResult = spfResult
	spfIdentity := dmarc.SPFIdentity{Domain: spfDomain}
	if spfResult != nil {
		spfIdentity.Passed = spfResult.Status == spf.Pass
		spfIdentity.TemporaryError = spfResult.Status == spf.TempError
	}
	for _, policy := range policies {
		sample, sampleErr := rand.Int(rand.Reader, big.NewInt(100))
		if sampleErr != nil {
			return result, fmt.Errorf("failed to sample DMARC policy: %w", sampleErr)
		}
		candidate, evalErr := dmarc.EvaluatePolicy(policy.record, policy.domain, signatures, spfIdentity, int(sample.Int64()))
		if evalErr != nil {
			return result, evalErr
		}
		if evaluationRank(candidate) > evaluationRank(result) {
			result = candidate
		}
	}
	return result, nil
}

// A multi-valued From is evaluated once per domain. The strictest failing
// policy is selected, as described by RFC 7489 §6.6.1.
func evaluationRank(e dmarc.Evaluation) int {
	if e.Status == dmarc.EvaluationFail {
		// Compare the action applied to this message before the published
		// policy; sampling can reduce a reject policy to quarantine.
		rank := 3
		switch e.Disposition {
		case dmarc.PolicyReject:
			rank += 6
		case dmarc.PolicyQuarantine:
			rank += 3
		}
		switch e.Policy {
		case dmarc.PolicyReject:
			rank += 2
		case dmarc.PolicyQuarantine:
			rank++
		}
		return rank
	}
	if e.Status == dmarc.EvaluationTempError {
		return 2
	}
	if e.Status == dmarc.EvaluationPass {
		return 1
	}
	return 0
}

func authorDomainsFromHeaders(fields headers) ([]string, error) {
	var from string
	for _, field := range fields {
		name, value, ok := strings.Cut(field, ":")
		if !ok || !header.EqualASCIIFold(name, "From") {
			continue
		}
		if from != "" {
			return nil, fmt.Errorf("multiple RFC5322.From fields")
		}
		from = value
	}
	if from == "" {
		return nil, fmt.Errorf("missing RFC5322.From field")
	}
	from = strings.TrimSpace(from)
	from = strings.NewReplacer("\r\n ", " ", "\r\n\t", " ").Replace(from)
	if hasTopLevelGroupColon(from) {
		return nil, fmt.Errorf("RFC5322.From contains a group instead of a mailbox-list")
	}
	addresses, err := mail.ParseAddressList(from)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("RFC5322.From contains no valid mailbox")
	}
	var domains []string
	seen := make(map[string]bool)
	for _, mailbox := range addresses {
		address := mailbox.Address
		at := strings.LastIndexByte(address, '@')
		if at < 0 || at == len(address)-1 {
			return nil, fmt.Errorf("invalid RFC5322.From mailbox")
		}
		domain := address[at+1:]
		if !seen[strings.ToLower(domain)] {
			domains = append(domains, domain)
			seen[strings.ToLower(domain)] = true
		}
	}
	// Preserve the source spelling; EvaluateDMARC normalizes and deduplicates
	// domains before policy lookup and sampling.
	return domains, nil
}

// RFC 5322 From is a mailbox-list. A colon outside quoted strings, comments,
// angle addresses, or address literals starts a group, which is only valid in
// an address-list.
func hasTopLevelGroupColon(value string) bool {
	quoted, escaped := false, false
	commentDepth, angleDepth, literalDepth := 0, 0, 0
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if escaped {
			escaped = false
			continue
		}
		if (quoted || commentDepth > 0) && ch == '\\' {
			escaped = true
			continue
		}
		if commentDepth > 0 {
			switch ch {
			case '(':
				commentDepth++
			case ')':
				commentDepth--
			}
			continue
		}
		if quoted {
			if ch == '"' {
				quoted = false
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '(':
			commentDepth++
		case '<':
			angleDepth++
		case '>':
			angleDepth--
		case '[':
			literalDepth++
		case ']':
			literalDepth--
		case ':':
			if angleDepth == 0 && literalDepth == 0 {
				return true
			}
		}
	}
	return false
}
