package dkim2

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/masa23/mmauth/domainkey"
)

// DSNVerifyOptions identifies the receiving system's signing domains. List the
// exact d= domains it uses; suffix matching alone cannot establish ownership.
type DSNVerifyOptions struct {
	Verification VerifyOptions
	LocalDomains []string
}

// DSNResult distinguishes authentication of the DSN itself from the additional
// checks on its embedded original message required by draft-09 section 16.4.
// Only Status == Pass authorizes PropagateDSN. None means that the embedded
// message or the DSN is not DKIM2 signed. Original is returned only on Pass.
type DSNResult struct {
	Status         Status
	Err            error
	Authentication Result
	Original       []byte
	HeadersOnly    bool
	// ReportingMTA and Recipients are the authenticated report's claims,
	// returned only on Pass. Authentication does not establish their truth
	// or replace the receiving MTA's delivery policy.
	ReportingMTA string
	Recipients   []DSNRecipient
}

// VerifyDSN fully authenticates a DKIM2 DSN, confirms the original's latest
// signature belongs to this system, and checks its signature and current
// hashes. Headers-only returns do not claim that the omitted body was checked.
// It does not send mail or apply the caller's replay/delivery policy.
func VerifyDSN(wire []byte, envelope Envelope, options DSNVerifyOptions) DSNResult {
	verification, err := dsnVerificationOptions(options)
	if err != nil {
		return DSNResult{Status: PermError, Err: err}
	}
	auth := Verify(wire, envelope, verification)
	result := DSNResult{Status: auth.Status, Err: auth.Err, Authentication: auth}
	if auth.Status != Pass {
		return result
	}
	fail := func(status Status, err error) DSNResult {
		result.Status, result.Err = status, err
		return result
	}
	if envelope.MailFrom != "<>" {
		return fail(Fail, errors.New("dkim2: DSN requires a null SMTP MAIL FROM"))
	}
	dsn, err := parseDSN(wire)
	if err != nil {
		return fail(PermError, err)
	}
	original, err := Parse(dsn.original)
	if err != nil {
		return fail(PermError, fmt.Errorf("dkim2: invalid DSN original: %w", err))
	}
	if len(original.Signatures) == 0 && len(original.Instances) == 0 {
		return fail(None, nil)
	}
	if err := authenticateDSNOriginal(original, dsn.headersOnly, options.LocalDomains, verification); err != nil {
		failure := provisionalFailure(err)
		return fail(failure.Status, failure.Err)
	}
	latest := original.Signatures[len(original.Signatures)-1]
	// The report's origin, not its latest forwarder, must have handled one of
	// the original's recipients (section 7.1 item 4 / section 16.4 item 1).
	if !recipientMatchesSigner(latest.Recipients, dsn.message.Signatures[0].Domain) {
		return fail(Fail, errors.New("dkim2: DSN origin does not match the original recipients"))
	}
	actual, err := normalizeEnvelope(envelope)
	if err != nil {
		return fail(Fail, err)
	}
	for _, recipient := range actual.RcptTo {
		if !equalPath(recipient, latest.MailFrom) {
			return fail(Fail, errors.New("dkim2: DSN recipient does not match original MAIL FROM"))
		}
	}
	result.Original = append([]byte(nil), dsn.original...)
	result.HeadersOnly = dsn.headersOnly
	result.ReportingMTA = dsn.reportingMTA
	result.Recipients = append([]DSNRecipient(nil), dsn.recipients...)
	return result
}

// Share one DNS budget between outer and embedded authentication. Verify adds
// its own wrapper, but this outer resolver still enforces the aggregate cap.
func dsnVerificationOptions(options DSNVerifyOptions) (VerifyOptions, error) {
	if len(options.LocalDomains) == 0 {
		return VerifyOptions{}, errors.New("dkim2: DSN verification requires local signing domains")
	}
	for _, domain := range options.LocalDomains {
		if !validDomain(domain) {
			return VerifyOptions{}, errors.New("dkim2: invalid local DSN signing domain")
		}
	}
	o := options.Verification
	if o.MaxDNSLookups < 0 || o.DNSBudget < 0 {
		return o, errors.New("dkim2: invalid DNS verification budget")
	}
	base := o.Resolver
	if base == nil {
		base = domainkey.NewDefaultTXTResolver()
	}
	max := o.MaxDNSLookups
	if max == 0 {
		max = maxVerificationDNSLookups
	}
	budget := o.DNSBudget
	if budget == 0 {
		budget = maxVerificationDNSTime
	}
	o.Resolver = &verificationResolver{base: base, max: max, deadline: time.Now().Add(budget)}
	return o, nil
}

func localSigningDomain(domain string, local []string) bool {
	for _, candidate := range local {
		if strings.EqualFold(domain, candidate) {
			return true
		}
	}
	return false
}

func authenticateDSNOriginal(m *Message, headersOnly bool, local []string, options VerifyOptions) error {
	if err := validateProvisionalStructure(m); err != nil {
		return &statusError{PermError, err}
	}
	latest := m.Signatures[len(m.Signatures)-1]
	inst := m.Instances[len(m.Instances)-1]
	if latest.Instance != inst.Number {
		return errors.New("dkim2: DSN original's latest m= does not match")
	}
	if latest.NextDomain != "" || latest.MailFrom == "<>" {
		return errors.New("dkim2: DSN original has no returnable MAIL FROM")
	}
	if !localSigningDomain(latest.Domain, local) || !domainMatch(pathDomain(latest.MailFrom), latest.Domain) {
		return errors.New("dkim2: DSN original's last hop is not a local sender")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	if latest.Timestamp > now.Unix()+24*60*60 || now.Unix()-latest.Timestamp > 14*24*60*60 {
		return errors.New("dkim2: DSN original's last signature is outside the time window")
	}
	current := latest
	current.Instance = len(m.Instances)
	if err := checkSignature(m.Instances, m.Signatures[:len(m.Signatures)-1], current, options.Resolver); err != nil {
		return err
	}
	return checkInstanceHashWithBody(m, inst, !headersOnly)
}
