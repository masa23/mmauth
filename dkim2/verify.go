package dkim2

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

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
	// Testing means at least one key had t=y. Such mail is reported as None.
	Testing bool
	// UnverifiedBodies lists preceding instances whose body could not be
	// reconstructed because a later Message-Instance used a null body Recipe.
	UnverifiedBodies []int
	// ReplayID identifies the first signed message instance after successful
	// cryptographic verification. It is empty for unauthenticated results.
	ReplayID string
}

// VerifyOptions selects a DNS resolver and evaluation time. By default it
// uses the system DNS resolver and the current time.
type VerifyOptions struct {
	Resolver domainkey.TXTResolver
	Now      time.Time
	// ValidateNextDomain must confirm an out-of-band arrangement when the
	// highest signature uses nd= and therefore has no signed SMTP paths.
	ValidateNextDomain func(Signature, Envelope) error
	// AllowPartialBody permits verification across a null body Recipe. The
	// result lists every body instance that could not be authenticated.
	AllowPartialBody bool
	// ReplayCheck atomically checks and records a ReplayID. It returns true if
	// this message was already seen. It is skipped for exploded or testing mail.
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
	testing := false
	var unverifiedBodies []int
	replayID := ""
	finish := func(status Status, err error) Result {
		if testing && status != TempError {
			status = None
		}
		return Result{Status: status, Err: err, Testing: testing, UnverifiedBodies: append([]int(nil), unverifiedBodies...), ReplayID: replayID}
	}
	for i, sig := range m.Signatures {
		if sig.Timestamp > now.Unix() || now.Unix()-sig.Timestamp > 14*24*60*60 {
			return finish(PermError, fmt.Errorf("dkim2: signature i=%d is outside the 14-day time window", sig.Index))
		}
		if err := checkSignature(m.Instances, m.Signatures[:i], sig, resolver, &testing); err != nil {
			var testError *testingFailure
			if errors.As(err, &testError) {
				return finish(None, err)
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
		if testing {
			return finish(None, err)
		}
		return finish(PermError, err)
	}
	state := m
	bodyKnown := true
	for i := len(m.Instances) - 1; i >= 0; i-- {
		if err := checkInstanceHashWithBody(state, m.Instances[i], bodyKnown); err != nil {
			if testing {
				return finish(None, err)
			}
			return finish(Fail, err)
		}
		if !bodyKnown {
			unverifiedBodies = append(unverifiedBodies, m.Instances[i].Number)
		}
		if i > 0 {
			r, err := parseRecipe(m.Instances[i].Recipe)
			if err != nil {
				return finish(PermError, err)
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
	for i, sig := range m.Signatures {
		for _, prior := range m.Signatures[:i] {
			if hasFlag(prior.Flags, "donotmodify") && sig.Instance > prior.Instance {
				err := fmt.Errorf("dkim2: message changed after donotmodify in signature i=%d", prior.Index)
				if testing {
					return finish(None, err)
				}
				return finish(Fail, err)
			}
			if hasFlag(prior.Flags, "donotexplode") && hasFlag(sig.Flags, "exploded") {
				err := fmt.Errorf("dkim2: message exploded after donotexplode in signature i=%d", prior.Index)
				if testing {
					return finish(None, err)
				}
				return finish(Fail, err)
			}
		}
	}
	sort.Ints(unverifiedBodies)
	if !testing {
		replayID = firstInstanceReplayID(m.Instances[0])
		if options.ReplayCheck != nil {
			exploded := false
			for _, sig := range m.Signatures {
				if hasFlag(sig.Flags, "exploded") {
					exploded = true
					break
				}
			}
			if !exploded {
				duplicate, err := options.ReplayCheck(replayID)
				if err != nil {
					return finish(TempError, fmt.Errorf("dkim2: replay check failed: %w", err))
				}
				if duplicate {
					return finish(Fail, errors.New("dkim2: unexpected replay"))
				}
			}
		}
	}
	return finish(Pass, nil)
}

func firstInstanceReplayID(inst Instance) string {
	for _, algorithm := range []string{"sha256", "sha512"} {
		for _, h := range inst.Hashes {
			if h.Algorithm == algorithm {
				return algorithm + ":" + h.Header + ":" + h.Body
			}
		}
	}
	return "" // A successful verification always has a supported hash.
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
	checked := 0
	for _, h := range inst.Hashes {
		if h.Algorithm != "sha256" && h.Algorithm != "sha512" {
			continue
		}
		checked++
		hh, err := headerDigest(m.Headers, h.Algorithm)
		if err != nil {
			return err
		}
		if hh != h.Header {
			return fmt.Errorf("dkim2: Message-Instance m=%d %s header hash mismatch", inst.Number, h.Algorithm)
		}
		if checkBody {
			bh, err := bodyDigest(m.Body, h.Algorithm)
			if err != nil {
				return err
			}
			if bh != h.Body {
				return fmt.Errorf("dkim2: Message-Instance m=%d %s body hash mismatch", inst.Number, h.Algorithm)
			}
		}
	}
	if checked == 0 {
		return errors.New("dkim2: no supported Message-Instance hash")
	}
	return nil
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
		if i > 0 && signatures[i-1].NextDomain == "" && !recipientDomainMatches(signatures[i-1].Recipients, custodyDomain) {
			return fmt.Errorf("dkim2: broken chain of custody at signature i=%d", sig.Index)
		}
	}
	return nil
}

type temporaryDNSError struct{ err error }

func (e *temporaryDNSError) Error() string { return e.err.Error() }
func (e *temporaryDNSError) Unwrap() error { return e.err }

type permanentKeyError struct{ err error }

func (e *permanentKeyError) Error() string { return e.err.Error() }
func (e *permanentKeyError) Unwrap() error { return e.err }

type testingFailure struct{ err error }

func (e *testingFailure) Error() string { return e.err.Error() }
func (e *testingFailure) Unwrap() error { return e.err }

type keyData struct {
	public  interface{}
	testing bool
}

func lookupKey(resolver domainkey.TXTResolver, domain, selector, algorithm string) (interface{}, error) {
	name := selector + "._domainkey." + domain
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, &permanentKeyError{fmt.Errorf("dkim2: key %s does not exist: %w", name, err)}
		}
		return nil, &temporaryDNSError{fmt.Errorf("dkim2: key %s lookup failed: %w", name, err)}
	}
	if len(records) != 1 {
		return nil, &permanentKeyError{fmt.Errorf("dkim2: key %s has %d TXT records", name, len(records))}
	}
	raw := records[0]
	seen := make(map[string]bool)
	keyType := "rsa" // The DNS key draft defaults k= to rsa only when absent.
	for index, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, value, ok := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" || seen[k] {
			return nil, &permanentKeyError{errors.New("dkim2: malformed or duplicate key tag")}
		}
		seen[k] = true
		if k == "k" {
			keyType = strings.TrimSpace(value)
			if keyType != "rsa" && keyType != "ed25519" {
				return nil, &permanentKeyError{fmt.Errorf("dkim2: unsupported key type %q", keyType)}
			}
		}
		if k == "v" && index != 0 {
			return nil, &permanentKeyError{errors.New("dkim2: v= is not the first key tag")}
		}
	}
	if !seen["p"] {
		return nil, &permanentKeyError{errors.New("dkim2: missing p= key tag")}
	}
	key, err := domainkey.ParseDomainKeyRecord(raw)
	if err != nil {
		return nil, &permanentKeyError{err}
	}
	if key.Version != "" && key.Version != "DKIM1" {
		return nil, &permanentKeyError{errors.New("dkim2: invalid key version")}
	}
	if key.PublicKey == "" {
		return nil, &permanentKeyError{errors.New("dkim2: revoked key")}
	}
	// The s= service tag is retired by the DKIM2 key draft.
	if algorithm == "rsa-sha256" && keyType != "rsa" {
		return nil, &permanentKeyError{errors.New("dkim2: key algorithm mismatch")}
	}
	if algorithm == "ed25519-sha256" && keyType != "ed25519" {
		return nil, &permanentKeyError{errors.New("dkim2: key algorithm mismatch")}
	}
	decoded, err := b64(key.PublicKey)
	if err != nil {
		return nil, &permanentKeyError{fmt.Errorf("dkim2: invalid public key base64: %w", err)}
	}
	if keyType == "ed25519" {
		if len(decoded) != ed25519.PublicKeySize {
			return nil, &permanentKeyError{errors.New("dkim2: invalid Ed25519 public key length")}
		}
		return keyData{ed25519.PublicKey(decoded), key.IsTestFlag()}, nil
	}
	pub, err := x509.ParsePKCS1PublicKey(decoded)
	if err != nil {
		return nil, &permanentKeyError{fmt.Errorf("dkim2: invalid PKCS#1 RSA public key: %w", err)}
	}
	return keyData{pub, key.IsTestFlag()}, nil
}

func checkSignature(instances []Instance, previous []Signature, sig Signature, resolver domainkey.TXTResolver, testing *bool) error {
	input, err := signatureInput(instances[:sig.Instance], previous, sig.Raw)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(input)
	checked := 0
	for _, v := range sig.Values {
		if v.Algorithm != "rsa-sha256" && v.Algorithm != "ed25519-sha256" {
			continue
		}
		checked++
		found, err := lookupKey(resolver, sig.Domain, v.Selector, v.Algorithm)
		if err != nil {
			return err
		}
		key := found.(keyData)
		if key.testing {
			*testing = true
		}
		decoded, err := b64(v.Value)
		if err != nil {
			return err
		}
		switch v.Algorithm {
		case "rsa-sha256":
			pub, ok := key.public.(*rsa.PublicKey)
			if !ok || pub.N.BitLen() < 1024 || pub.E != 65537 {
				return &permanentKeyError{errors.New("dkim2: invalid RSA verification key")}
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], decoded); err != nil {
				failure := fmt.Errorf("dkim2: signature i=%d selector %s failed: %w", sig.Index, v.Selector, err)
				if key.testing {
					return &testingFailure{failure}
				}
				return failure
			}
		case "ed25519-sha256":
			pub, ok := key.public.(ed25519.PublicKey)
			if !ok || !ed25519.Verify(pub, hash[:], decoded) {
				failure := fmt.Errorf("dkim2: signature i=%d selector %s failed", sig.Index, v.Selector)
				if key.testing {
					return &testingFailure{failure}
				}
				return failure
			}
		}
	}
	if checked == 0 {
		return &permanentKeyError{errors.New("dkim2: no supported signature algorithm")}
	}
	return nil
}
