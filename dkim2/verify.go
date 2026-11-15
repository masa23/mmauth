package dkim2

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/masa23/mmauth/domainkey"
)

// Status is a DKIM2 authentication result.
type Status string

const (
	None      Status = "none"
	Pass      Status = "pass"
	Fail      Status = "fail"
	PermError Status = "permerror"
	TempError Status = "temperror"
)

// Result reports the complete chain's status and the first error encountered.
type Result struct {
	Status Status
	Err    error
	// Testing is retained for API compatibility and is always false; DNS t=y
	// is ignored by DKIM2 under the current DNS draft.
	Testing bool
	// UnverifiedBodies lists preceding instances whose body could not be
	// reconstructed because a later Message-Instance used a null body Recipe.
	UnverifiedBodies []int
	// ReplayID identifies the first signed message instance after successful
	// cryptographic verification. It is empty for unauthenticated results.
	ReplayID string
	// ReplayDetected and ReplayErr report local replay-policy observations.
	// They do not change the DKIM2 authentication status.
	ReplayDetected bool
	ReplayErr      error
}

// VerifyOptions selects a DNS resolver and evaluation time. By default it
// uses the system DNS resolver and the current time.
type VerifyOptions struct {
	Resolver domainkey.TXTResolver
	Now      time.Time
	// ValidateNextDomain may confirm an out-of-band arrangement for a highest
	// nd= signature. Such a message remains not fully verified until another
	// signature records mf= and rt=.
	ValidateNextDomain func(Signature, Envelope) error
	// AllowPartialBody continues checking headers across a null body Recipe.
	// The result remains PermError and lists bodies that were not authenticated.
	AllowPartialBody bool
	// ReplayCheck atomically checks and records a ReplayID. It returns true if
	// this message was already seen. It is skipped for exploded mail. The
	// outcome is reported separately from DKIM2 authentication.
	ReplayCheck func(string) (bool, error)
}

// Verify validates the DKIM2 chain and all reconstructable message instances.
func Verify(wire []byte, envelope Envelope, options VerifyOptions) Result {
	m, err := Parse(wire)
	if err != nil {
		return Result{Status: PermError, Err: err}
	}
	if len(m.Instances) == 0 && len(m.Signatures) == 0 {
		return Result{Status: None}
	}
	if err := validateStructure(m); err != nil {
		return Result{Status: PermError, Err: err}
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = domainkey.NewDefaultTXTResolver()
	}
	var unverifiedBodies []int
	replayID := ""
	var replayDetected bool
	var replayErr error
	finish := func(status Status, err error) Result {
		return Result{Status: status, Err: err, UnverifiedBodies: append([]int(nil), unverifiedBodies...), ReplayID: replayID, ReplayDetected: replayDetected, ReplayErr: replayErr}
	}
	for i, sig := range m.Signatures {
		if sig.Timestamp > now.Unix()+24*60*60 || now.Unix()-sig.Timestamp > 14*24*60*60 {
			return finish(Fail, fmt.Errorf("dkim2: signature i=%d is outside the time window", sig.Index))
		}
		if err := checkSignature(m.Instances, m.Signatures[:i], sig, resolver); err != nil {
			var statusErr *statusError
			if errors.As(err, &statusErr) {
				return finish(statusErr.status, err)
			}
			var dnsError *temporaryDNSError
			if errors.As(err, &dnsError) {
				return finish(TempError, err)
			}
			var keyError *permanentKeyError
			if errors.As(err, &keyError) {
				return finish(PermError, err)
			}
			return finish(Fail, err)
		}
	}
	if err := checkEnvelope(envelope, m.Signatures, options.ValidateNextDomain); err != nil {
		return finish(Fail, err)
	}
	state := m
	bodyKnown := true
	for i := len(m.Instances) - 1; i >= 0; i-- {
		if err := checkInstanceHashWithBody(state, m.Instances[i], bodyKnown); err != nil {
			var statusErr *statusError
			if errors.As(err, &statusErr) {
				return finish(statusErr.status, err)
			}
			return finish(Fail, err)
		}
		if !bodyKnown {
			unverifiedBodies = append(unverifiedBodies, m.Instances[i].Number)
		}
		if i == 0 {
			if m.Instances[i].Recipe != "" {
				if _, err := parseRecipe(m.Instances[i].Recipe); err != nil {
					return finish(PermError, err)
				}
			}
			if err := checkAuthenticFrom(state.Headers, m.Signatures[0].Domain, resolver); err != nil {
				return finish(fromErrorStatus(err), err)
			}
		}
		if i > 0 && m.Instances[i].Recipe != "" {
			r, err := parseRecipe(m.Instances[i].Recipe)
			if err != nil {
				return finish(PermError, err)
			}
			if _, changed := r.Headers["from"]; changed {
				for _, sig := range m.Signatures {
					if sig.Instance >= m.Instances[i].Number {
						if err := checkAuthenticFrom(state.Headers, sig.Domain, resolver); err != nil {
							return finish(fromErrorStatus(err), err)
						}
						break
					}
				}
			}
			if r.NullBody {
				if !options.AllowPartialBody {
					return finish(PermError, errors.New("dkim2: null body Recipe requires AllowPartialBody"))
				}
				bodyKnown = false
			}
			if !bodyKnown {
				r.HasBody = false // Continue reconstructing and checking headers.
				r.NullBody = false
			}
			state, err = applyRecipe(state, r)
			if err != nil {
				return finish(PermError, err)
			}
		}
	}
	sort.Ints(unverifiedBodies)
	if len(unverifiedBodies) > 0 {
		return finish(PermError, errors.New("dkim2: null body Recipe prevents full verification"))
	}
	replayID = firstInstanceReplayID(state, m.Instances[0])
	if options.ReplayCheck != nil {
		exploded := false
		for _, sig := range m.Signatures {
			if hasFlag(sig.Flags, "exploded") {
				exploded = true
				break
			}
		}
		if !exploded {
			replayDetected, replayErr = options.ReplayCheck(replayID)
		}
	}
	return finish(Pass, nil)
}

func firstInstanceReplayID(state *Message, inst Instance) string {
	groups := inst.HashGroups
	if len(groups) == 0 {
		groups = [][]HashSet{inst.Hashes}
	}
	for _, group := range groups {
		if checkInstanceHashWithBody(state, Instance{Number: inst.Number, Hashes: group}, true) == nil {
			for _, hash := range group {
				if hash.Algorithm == "sha256" || hash.Algorithm == "sha512" {
					return hash.Algorithm + ":" + hash.Header + ":" + hash.Body
				}
			}
		}
	}
	return "" // Successful full verification has a passing supported group.
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

func checkInstanceHash(m *Message, inst Instance) error {
	return checkInstanceHashWithBody(m, inst, true)
}

func checkInstanceHashWithBody(m *Message, inst Instance, checkBody bool) error {
	groups := inst.HashGroups
	if len(groups) == 0 {
		groups = [][]HashSet{inst.Hashes}
	}
	overall := PermError
	var chosenErr error
	for _, group := range groups {
		groupStatus := Pass
		groupErrors := make(map[Status]error)
		for _, h := range group {
			status := Pass
			var err error
			if h.Algorithm != "sha256" && h.Algorithm != "sha512" {
				status, err = PermError, fmt.Errorf("dkim2: Message-Instance m=%d algorithm %s unknown", inst.Number, h.Algorithm)
			} else {
				var hh string
				hh, err = headerDigest(m.Headers, h.Algorithm)
				if err != nil {
					status = PermError
				}
				if err == nil && hh != h.Header {
					status, err = Fail, fmt.Errorf("dkim2: Message-Instance m=%d %s header hash mismatch", inst.Number, h.Algorithm)
				}
				if err == nil && checkBody {
					var bh string
					bh, err = bodyDigest(m.Body, h.Algorithm)
					if err != nil {
						status = PermError
					}
					if err == nil && bh != h.Body {
						status, err = Fail, fmt.Errorf("dkim2: Message-Instance m=%d %s body hash mismatch", inst.Number, h.Algorithm)
					}
				}
			}
			if err != nil && groupErrors[status] == nil {
				groupErrors[status] = err
			}
			if status == Fail {
				groupStatus = Fail
			} else if status == PermError && groupStatus == Pass {
				groupStatus = PermError
			}
		}
		if groupStatus == Pass {
			return nil
		}
		if groupStatus == Fail {
			if overall != Fail {
				chosenErr = groupErrors[Fail]
			}
			overall = Fail
		} else if overall == PermError && chosenErr == nil {
			chosenErr = groupErrors[PermError]
		}
	}
	if chosenErr == nil {
		chosenErr = fmt.Errorf("dkim2: Message-Instance m=%d no group of hashes passed", inst.Number)
	}
	return &statusError{overall, chosenErr}
}

func recipientDomainMatches(recipients []string, mailFromDomain string) bool {
	if mailFromDomain == "" {
		return false
	}
	for _, p := range recipients {
		if domainMatch(mailFromDomain, pathDomain(p)) {
			return true
		}
	}
	return false
}

func recipientMatchesSigner(recipients []string, signingDomain string) bool {
	for _, path := range recipients {
		if domainMatch(pathDomain(path), signingDomain) {
			return true
		}
	}
	return false
}

func equalPath(a, b string) bool {
	if a == "<>" || b == "<>" {
		return a == b
	}
	return normalizedPath(a) == normalizedPath(b)
}

func normalizedPath(p string) string {
	inner := p[1 : len(p)-1]
	if strings.EqualFold(inner, "Postmaster") {
		return "<postmaster>"
	}
	if strings.HasPrefix(inner, "@") {
		route, mailbox, _ := strings.Cut(inner, ":")
		inner = strings.ToLower(route) + ":" + mailbox
	}
	at := strings.LastIndexByte(inner, '@')
	return "<" + inner[:at] + strings.ToLower(inner[at:]) + ">"
}

func checkEnvelope(envelope Envelope, signatures []Signature, validateNextDomain func(Signature, Envelope) error) error {
	var err error
	envelope, err = normalizeEnvelope(envelope)
	if err != nil {
		return err
	}
	if !validPath(envelope.MailFrom, true) || len(envelope.RcptTo) == 0 {
		return errors.New("dkim2: actual SMTP envelope is missing or invalid")
	}
	for _, p := range envelope.RcptTo {
		if !validPath(p, false) {
			return errors.New("dkim2: invalid actual RCPT TO")
		}
	}
	latest := signatures[len(signatures)-1]
	if latest.NextDomain != "" {
		if validateNextDomain == nil {
			return errors.New("dkim2: latest nd= requires out-of-band validation")
		}
		if err := validateNextDomain(latest, envelope); err != nil {
			return fmt.Errorf("dkim2: latest nd= validation failed: %w", err)
		}
	} else {
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
	}
	for i, sig := range signatures {
		if sig.NextDomain != "" {
			if i < len(signatures)-1 && !strings.EqualFold(sig.NextDomain, signatures[i+1].Domain) {
				return fmt.Errorf("dkim2: nd= in signature i=%d does not match next d=", sig.Index)
			}
		} else {
			if d := pathDomain(sig.MailFrom); d != "" && !domainMatch(d, sig.Domain) {
				return fmt.Errorf("dkim2: d= in signature i=%d does not match mf=", sig.Index)
			}
		}
		custodyDomain := pathDomain(sig.MailFrom)
		if sig.NextDomain != "" {
			custodyDomain = sig.Domain
		}
		if i > 0 && signatures[i-1].NextDomain == "" {
			matches := recipientDomainMatches(signatures[i-1].Recipients, custodyDomain)
			if sig.NextDomain != "" || sig.MailFrom == "<>" {
				matches = recipientMatchesSigner(signatures[i-1].Recipients, sig.Domain)
			}
			if !matches {
				return fmt.Errorf("dkim2: broken chain of custody at signature i=%d", sig.Index)
			}
		}
	}
	if latest.NextDomain != "" {
		return errors.New("dkim2: highest nd= cannot be fully verified before the next signature")
	}
	return nil
}

type temporaryDNSError struct{ err error }

func (e *temporaryDNSError) Error() string { return e.err.Error() }
func (e *temporaryDNSError) Unwrap() error { return e.err }

type permanentKeyError struct{ err error }

func (e *permanentKeyError) Error() string { return e.err.Error() }
func (e *permanentKeyError) Unwrap() error { return e.err }

type keyData struct {
	public interface{}
}

type statusError struct {
	status Status
	err    error
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

func combinedSignatureStatus(all []Status) Status {
	hasTemp, hasPerm := false, false
	for _, status := range all {
		if status == Fail {
			return Fail
		}
		if status == TempError {
			hasTemp = true
		}
		if status == PermError {
			hasPerm = true
		}
	}
	if hasPerm {
		return PermError
	}
	if hasTemp {
		return TempError
	}
	return Pass
}

func checkSignature(instances []Instance, previous []Signature, sig Signature, resolver domainkey.TXTResolver) error {
	input, err := signatureInput(instances[:sig.Instance], previous, sig.Raw)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(input)
	groups := sig.ValueGroups
	if len(groups) == 0 {
		groups = [][]SignatureValue{sig.Values}
	}
	overall := PermError
	var chosenErr error
	for _, group := range groups {
		var statuses []Status
		groupErrors := make(map[Status]error)
		for _, value := range group {
			status, err := checkOneSignature(input, hash[:], sig, value, resolver)
			statuses = append(statuses, status)
			if err != nil && groupErrors[status] == nil {
				groupErrors[status] = err
			}
		}
		status := combinedSignatureStatus(statuses)
		if status == Pass {
			return nil
		}
		if status == TempError || status == Fail && overall == PermError {
			overall = status
			chosenErr = groupErrors[status]
		} else if chosenErr == nil && status == overall {
			chosenErr = groupErrors[status]
		}
	}
	if chosenErr == nil {
		chosenErr = fmt.Errorf("dkim2: DKIM2-Signature i=%d no group of signatures passed", sig.Index)
	}
	return &statusError{overall, chosenErr}
}

func checkOneSignature(input, hash []byte, sig Signature, value SignatureValue, resolver domainkey.TXTResolver) (Status, error) {
	switch value.Algorithm {
	case "rsa-sha256", "ed25519-sha256", "mldsa44":
	default:
		return PermError, fmt.Errorf("dkim2: DKIM2-Signature i=%d selector %s algorithm unknown", sig.Index, value.Selector)
	}
	key, err := lookupKey(resolver, sig.Domain, value.Selector, value.Algorithm)
	if err != nil {
		var temporary *temporaryDNSError
		if errors.As(err, &temporary) {
			return TempError, err
		}
		return PermError, err
	}
	decoded, err := b64(value.Value)
	if err != nil {
		return PermError, err
	}
	valid := false
	switch value.Algorithm {
	case "rsa-sha256":
		pub, ok := key.public.(*rsa.PublicKey)
		if ok && pub.E == 65537 {
			valid = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, decoded) == nil
		}
	case "ed25519-sha256":
		pub, ok := key.public.(ed25519.PublicKey)
		valid = ok && ed25519.Verify(pub, hash, decoded)
	case "mldsa44":
		pub, ok := key.public.(*mldsa44.PublicKey)
		valid = ok && mldsa44.Verify(pub, input, []byte("DKIM2"), decoded)
	}
	if !valid {
		return Fail, fmt.Errorf("dkim2: DKIM2-Signature i=%d selector %s incorrect signature", sig.Index, value.Selector)
	}
	return Pass, nil
}
