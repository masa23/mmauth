package dkim2

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
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
}

// VerifyOptions selects a DNS resolver and evaluation time. By default it
// uses the system DNS resolver and the current time.
type VerifyOptions struct {
	Resolver domainkey.TXTResolver
	Now      time.Time
}

// Verify validates the DKIM2 chain and all reconstructable message instances.
func Verify(wire []byte, envelope Envelope, options VerifyOptions) Result {
	m, err := Parse(wire)
	if err != nil {
		return Result{PermError, err}
	}
	if len(m.Instances) == 0 && len(m.Signatures) == 0 {
		return Result{None, nil}
	}
	if err := validateStructure(m); err != nil {
		return Result{PermError, err}
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
	for i, sig := range m.Signatures {
		if sig.Timestamp > now.Unix() || now.Unix()-sig.Timestamp > 14*24*60*60 {
			return Result{PermError, fmt.Errorf("dkim2: signature i=%d is outside the 14-day time window", sig.Index)}
		}
		if err := checkSignature(m.Instances, m.Signatures[:i], sig, resolver, &testing); err != nil {
			var testError *testingFailure
			if errors.As(err, &testError) {
				return Result{None, err}
			}
			var dnsError *temporaryDNSError
			if errors.As(err, &dnsError) {
				return Result{TempError, err}
			}
			var keyError *permanentKeyError
			if errors.As(err, &keyError) {
				return Result{PermError, err}
			}
			return Result{Fail, err}
		}
	}
	if err := checkEnvelope(envelope, m.Signatures); err != nil {
		if testing {
			return Result{None, err}
		}
		return Result{PermError, err}
	}
	state := m
	for i := len(m.Instances) - 1; i >= 0; i-- {
		if err := checkInstanceHash(state, m.Instances[i]); err != nil {
			if testing {
				return Result{None, err}
			}
			return Result{Fail, err}
		}
		if i > 0 {
			r, err := parseRecipe(m.Instances[i].Recipe)
			if err != nil {
				return Result{PermError, err}
			}
			state, err = applyRecipe(state, r)
			if err != nil {
				return Result{PermError, err}
			}
		}
	}
	for i, sig := range m.Signatures {
		for _, prior := range m.Signatures[:i] {
			if hasFlag(prior.Flags, "donotmodify") && sig.Instance > prior.Instance {
				err := fmt.Errorf("dkim2: message changed after donotmodify in signature i=%d", prior.Index)
				if testing {
					return Result{None, err}
				}
				return Result{Fail, err}
			}
			if hasFlag(prior.Flags, "donotexplode") && hasFlag(sig.Flags, "exploded") {
				err := fmt.Errorf("dkim2: message exploded after donotexplode in signature i=%d", prior.Index)
				if testing {
					return Result{None, err}
				}
				return Result{Fail, err}
			}
		}
	}
	return Result{Pass, nil}
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
		bh, err := bodyDigest(m.Body, h.Algorithm)
		if err != nil {
			return err
		}
		if hh != h.Header {
			return fmt.Errorf("dkim2: Message-Instance m=%d %s header hash mismatch", inst.Number, h.Algorithm)
		}
		if bh != h.Body {
			return fmt.Errorf("dkim2: Message-Instance m=%d %s body hash mismatch", inst.Number, h.Algorithm)
		}
	}
	if checked == 0 {
		return errors.New("dkim2: no supported Message-Instance hash")
	}
	return nil
}

func recipientDomainMatches(recipients []string, mailFromDomain string) bool {
	if mailFromDomain == "" {
		return true
	} // Null reverse paths are permitted for DSNs.
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
	ia, ib := strings.LastIndexByte(a, '@'), strings.LastIndexByte(b, '@')
	return a[:ia] == b[:ib] && strings.EqualFold(a[ia:], b[ib:])
}

func checkEnvelope(envelope Envelope, signatures []Signature) error {
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
		return errors.New("dkim2: latest nd= requires out-of-band validation")
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
	for i, sig := range signatures {
		if sig.NextDomain != "" {
			if i == len(signatures)-1 || !strings.EqualFold(sig.NextDomain, signatures[i+1].Domain) {
				return fmt.Errorf("dkim2: nd= in signature i=%d does not match next d=", sig.Index)
			}
			continue
		}
		if d := pathDomain(sig.MailFrom); d != "" && !domainMatch(d, sig.Domain) {
			return fmt.Errorf("dkim2: d= in signature i=%d does not match mf=", sig.Index)
		}
		if i > 0 && signatures[i-1].NextDomain == "" && !recipientDomainMatches(signatures[i-1].Recipients, pathDomain(sig.MailFrom)) {
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
	for index, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, _, ok := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" || seen[k] {
			return nil, &permanentKeyError{errors.New("dkim2: malformed or duplicate key tag")}
		}
		seen[k] = true
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
	if !key.IsService(domainkey.ServiceTypeEmail) {
		return nil, &permanentKeyError{errors.New("dkim2: key is not enabled for email")}
	}
	if algorithm == "rsa-sha256" && key.KeyType != "" && key.KeyType != domainkey.KeyTypeRSA {
		return nil, &permanentKeyError{errors.New("dkim2: key algorithm mismatch")}
	}
	if algorithm == "ed25519-sha256" && key.KeyType != domainkey.KeyTypeED25519 {
		return nil, &permanentKeyError{errors.New("dkim2: key algorithm mismatch")}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
	if err != nil {
		return nil, &permanentKeyError{fmt.Errorf("dkim2: invalid public key base64: %w", err)}
	}
	if key.KeyType == domainkey.KeyTypeED25519 {
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
