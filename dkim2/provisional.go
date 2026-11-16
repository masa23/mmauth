package dkim2

import (
	"errors"
	"fmt"
	"time"

	"github.com/masa23/mmauth/domainkey"
)

// ProvisionalResult reports only the latest-hop checks in draft-09 section
// 13.2. Pass is not a Fully Verified DKIM2 Message: older signatures, custody,
// Recipes, and the Authentic From requirement have not been checked.
type ProvisionalResult struct {
	Status Status
	Err    error
	// PendingNextDomain means the highest nd= was accepted by the explicit
	// out-of-band validator. Standard DKIM2 DSN generation is not safe until
	// the receiving system has added its matching mf=/rt= signature.
	PendingNextDomain bool
}

// VerifyProvisional authenticates the most recent signature, current header and
// body hashes, and actual SMTP delivery envelope. Earlier fields are covered by
// that signature but their individual signatures and message instances are not
// verified. A Pass result is suitable for the provisional acceptance decision
// in draft-09 section 13.2, not a replacement for Verify.
// All fields still have to satisfy Parse's syntax and resource limits; malformed
// historical field syntax is rejected rather than interpreted ambiguously.
//
// The latest timestamp and the same DNS/resource budgets as Verify are applied.
// ReplayCheck is never called, and AllowPartialBody has no effect: the current
// body is always authenticated. A highest nd= needs ValidateNextDomain, and a
// successful arrangement is identified by PendingNextDomain.
func VerifyProvisional(wire []byte, envelope Envelope, options VerifyOptions) ProvisionalResult {
	m, err := Parse(wire)
	if err != nil {
		return ProvisionalResult{Status: PermError, Err: err}
	}
	if len(m.Instances) == 0 && len(m.Signatures) == 0 {
		return ProvisionalResult{Status: None}
	}
	if err := validateProvisionalStructure(m); err != nil {
		return ProvisionalResult{Status: PermError, Err: err}
	}
	if options.MaxDNSLookups < 0 || options.DNSBudget < 0 {
		return ProvisionalResult{Status: PermError, Err: errors.New("dkim2: invalid DNS verification budget")}
	}
	latest := m.Signatures[len(m.Signatures)-1]
	inst := m.Instances[len(m.Instances)-1]
	if latest.Instance != inst.Number {
		return ProvisionalResult{Status: Fail, Err: errors.New("dkim2: latest signature and Message-Instance m= do not match")}
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	if latest.Timestamp > now.Unix()+24*60*60 || now.Unix()-latest.Timestamp > 14*24*60*60 {
		return ProvisionalResult{Status: Fail, Err: fmt.Errorf("dkim2: signature i=%d is outside the time window", latest.Index)}
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = domainkey.NewDefaultTXTResolver()
	}
	maxLookups := options.MaxDNSLookups
	if maxLookups == 0 {
		maxLookups = maxVerificationDNSLookups
	}
	budget := options.DNSBudget
	if budget == 0 {
		budget = maxVerificationDNSTime
	}
	resolver = &verificationResolver{base: resolver, max: maxLookups, deadline: time.Now().Add(budget)}
	// checkSignature's slice bound is an array position, whereas an incomplete
	// historical chain may have gaps in m=. The signed Raw field stays intact;
	// all available Message-Instance fields are numbered <= the latest m=.
	current := latest
	current.Instance = len(m.Instances)
	if err := checkSignature(m.Instances, m.Signatures[:len(m.Signatures)-1], current, resolver); err != nil {
		return provisionalFailure(err)
	}
	if err := checkInstanceHash(m, inst); err != nil {
		return provisionalFailure(err)
	}
	if err := checkProvisionalEnvelope(envelope, latest, options.ValidateNextDomain); err != nil {
		return provisionalFailure(err)
	}
	return ProvisionalResult{Status: Pass, PendingNextDomain: latest.NextDomain != ""}
}

// Gaps in the historical sequence do not invalidate the latest-hop assessment.
// Duplicates are ambiguous and must never influence signature canonicalization.
func validateProvisionalStructure(m *Message) error {
	if len(m.Instances) == 0 || len(m.Signatures) == 0 {
		return errors.New("dkim2: missing Message-Instance or DKIM2-Signature")
	}
	for i := 1; i < len(m.Instances); i++ {
		if m.Instances[i-1].Number == m.Instances[i].Number {
			return errors.New("dkim2: duplicate Message-Instance number")
		}
	}
	for i := 1; i < len(m.Signatures); i++ {
		if m.Signatures[i-1].Index == m.Signatures[i].Index {
			return errors.New("dkim2: duplicate DKIM2-Signature number")
		}
	}
	latest := m.Signatures[len(m.Signatures)-1]
	if latest.Index == 1 && hasFlag(latest.Flags, "exploded") {
		return errors.New("dkim2: DKIM2-Signature i=1 has exploded flag")
	}
	return nil
}

func checkProvisionalEnvelope(envelope Envelope, latest Signature, validator func(Signature, Envelope) error) error {
	var err error
	envelope, err = normalizeEnvelope(envelope)
	if err != nil {
		return err
	}
	if !validPath(envelope.MailFrom, true) || len(envelope.RcptTo) == 0 {
		return errors.New("dkim2: actual SMTP envelope is missing or invalid")
	}
	for _, path := range envelope.RcptTo {
		if !validPath(path, false) {
			return errors.New("dkim2: invalid actual RCPT TO")
		}
	}
	if latest.NextDomain != "" {
		if validator == nil {
			return errors.New("dkim2: latest nd= requires out-of-band validation")
		}
		if err := validator(latest, envelope); err != nil {
			return fmt.Errorf("dkim2: latest nd= validation failed: %w", err)
		}
		return nil
	}
	if !equalPath(envelope.MailFrom, latest.MailFrom) {
		return errors.New("dkim2: actual MAIL FROM does not match mf=")
	}
	for _, actual := range envelope.RcptTo {
		found := false
		for _, recorded := range latest.Recipients {
			if equalPath(actual, recorded) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("dkim2: RCPT TO %q is missing from rt=", actual)
		}
	}
	if domain := pathDomain(latest.MailFrom); domain != "" && !domainMatch(domain, latest.Domain) {
		return errors.New("dkim2: latest signing domain does not match mf=")
	}
	return nil
}

func provisionalFailure(err error) ProvisionalResult {
	status := Fail
	var combined *statusError
	var temporary *temporaryDNSError
	var permanent *permanentKeyError
	switch {
	case errors.As(err, &combined):
		status = combined.status
	case errors.As(err, &temporary):
		status = TempError
	case errors.As(err, &permanent):
		status = PermError
	}
	return ProvisionalResult{Status: status, Err: err}
}
