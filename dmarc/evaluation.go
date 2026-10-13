package dmarc

import "fmt"

// EvaluationStatus is the result of applying RFC 7489 authentication and policy.
type EvaluationStatus string

const (
	EvaluationNone      EvaluationStatus = "none"
	EvaluationPass      EvaluationStatus = "pass"
	EvaluationFail      EvaluationStatus = "fail"
	EvaluationTempError EvaluationStatus = "temperror"
)

// DKIMIdentity describes one signature's authenticated identifier and result.
type DKIMIdentity struct {
	Domain         string
	Passed         bool
	TemporaryError bool
}

// SPFIdentity describes the RFC 7208 MAIL FROM identity (HELO for a null path).
type SPFIdentity struct {
	Domain         string
	Passed         bool
	TemporaryError bool
}

// Evaluation separates the published policy from the disposition recommended
// for this message. A temporary authentication failure never applies policy.
type Evaluation struct {
	Status      EvaluationStatus
	Alignment   AlignmentResult
	Policy      PolicyType
	Disposition PolicyType
	Sampled     bool
}

// EvaluatePolicy implements RFC 7489 §§6.6.2 and 6.6.4. sample is an integer
// in [0, 99], supplied by the caller so policy sampling is testable.
func EvaluatePolicy(record *Record, authorDomain string, dkim []DKIMIdentity, spf SPFIdentity, sample int) (Evaluation, error) {
	var result Evaluation
	if record == nil {
		return result, fmt.Errorf("DMARC record is nil")
	}
	if sample < 0 || sample >= 100 || record.Percent < 0 || record.Percent > 100 {
		return result, fmt.Errorf("invalid DMARC sampling value")
	}
	result.Policy = record.EffectivePolicy()
	if result.Policy != PolicyNone && result.Policy != PolicyQuarantine && result.Policy != PolicyReject {
		return Evaluation{}, fmt.Errorf("invalid DMARC policy")
	}
	result.Disposition = PolicyNone
	var err error
	authenticated := make([]AuthenticatedDomain, 0, len(dkim))
	for _, signature := range dkim {
		authenticated = append(authenticated, AuthenticatedDomain{Domain: signature.Domain, Passed: signature.Passed})
	}
	result.Alignment, err = EvaluateAlignment(record, authorDomain, authenticated, spf.Domain, spf.Passed)
	if err != nil {
		return Evaluation{}, err
	}
	if result.Alignment.Pass {
		result.Status = EvaluationPass
		return result, nil
	}
	// An unrelated temporary authentication failure cannot become an aligned
	// identifier after retry, so it must not prevent application of policy.
	author, authorOrg, err := alignmentDomain(authorDomain)
	if err != nil {
		return Evaluation{}, fmt.Errorf("invalid RFC5322.From domain: %w", err)
	}
	if spf.TemporaryError && domainsAligned(author, authorOrg, spf.Domain, record.AlignmentSPF) {
		result.Status = EvaluationTempError
		return result, nil
	}
	for _, signature := range dkim {
		if signature.TemporaryError && domainsAligned(author, authorOrg, signature.Domain, record.AlignmentDKIM) {
			result.Status = EvaluationTempError
			return result, nil
		}
	}
	result.Status = EvaluationFail
	result.Sampled = sample < record.Percent
	if result.Sampled {
		result.Disposition = result.Policy
	} else if result.Policy == PolicyReject {
		// RFC 7489 §6.6.4 applies the next less strict policy to unsampled mail.
		result.Disposition = PolicyQuarantine
	}
	return result, nil
}
