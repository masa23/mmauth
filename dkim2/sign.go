package dkim2

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/masa23/mmauth/domainkey"
)

// SignOptions supplies the private key and SMTP envelope for a DKIM2 hop.
// Timestamp defaults to the current time; HashAlgorithm defaults to sha256.
type SignOptions struct {
	Domain        string
	Selector      string
	Key           crypto.Signer
	Envelope      Envelope
	NextDomain    string // Use nd= instead of mf=/rt= for an imaginary hop.
	Timestamp     time.Time
	HashAlgorithm string
	Nonce         string
	Flags         []string
	// PolicyResolver supplies Domain Policy Records when a subdomain signs for
	// the From domain. Nil uses the system resolver.
	PolicyResolver domainkey.TXTResolver
	// AllowNullBodyRecipe explicitly allows Revise to use b:null. The caller
	// must have authenticated the incoming message before changing its body.
	AllowNullBodyRecipe bool
	// OutOfBandArrangement explicitly asserts an arrangement that permits
	// signing an incoming message without verifying its prior signatures here.
	// ForwardChecked and ReviseChecked authenticate the incoming message instead.
	OutOfBandArrangement bool
}

// Sign adds the first Message-Instance and DKIM2-Signature fields.
func Sign(wire []byte, options SignOptions) ([]byte, error) {
	m, err := Parse(wire)
	if err != nil {
		return nil, err
	}
	if len(m.Instances) != 0 || len(m.Signatures) != 0 {
		return nil, errors.New("dkim2: message is already signed; use Forward")
	}
	options, err = normalizeSignOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateSignOptions(options); err != nil {
		return nil, err
	}
	for _, flag := range options.Flags {
		if flag == "exploded" {
			return nil, errors.New("dkim2: initial signature cannot have exploded flag")
		}
	}
	if err := checkAuthenticFrom(m.Headers, options.Domain, options.PolicyResolver); err != nil {
		return nil, err
	}
	algorithm := options.HashAlgorithm
	if algorithm == "" {
		algorithm = "sha256"
	}
	hh, err := headerDigest(m.Headers, algorithm)
	if err != nil {
		return nil, err
	}
	bh, err := bodyDigest(m.Body, algorithm)
	if err != nil {
		return nil, err
	}
	mi := "Message-Instance: m=1; h=" + algorithm + ":" + foldBase64(hh) + ":" + foldBase64(bh) + ";\r\n"
	inst := Instance{Number: 1, Raw: mi, Hashes: []HashSet{{algorithm, hh, bh}}}
	sig, err := makeSignature([]Instance{inst}, nil, 1, options)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(mi)+len(sig)+len(wire))
	out = append(out, sig...)
	out = append(out, mi...)
	out = append(out, wire...)
	return out, nil
}

// Forward adds a signature for an unchanged message instance only when the
// caller explicitly asserts an out-of-band arrangement. Otherwise use
// ForwardChecked to authenticate the incoming message first.
func Forward(wire []byte, options SignOptions) ([]byte, error) {
	if !options.OutOfBandArrangement {
		return nil, errors.New("dkim2: Forward requires ForwardChecked or an explicit out-of-band arrangement")
	}
	return forward(wire, options)
}

func forward(wire []byte, options SignOptions) ([]byte, error) {
	m, err := Parse(wire)
	if err != nil {
		return nil, err
	}
	if err := validateStructure(m); err != nil {
		return nil, err
	}
	options, err = normalizeSignOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateSignOptions(options); err != nil {
		return nil, err
	}
	if err := checkInstanceHash(m, m.Instances[len(m.Instances)-1]); err != nil {
		return nil, err
	}
	previous := m.Signatures[len(m.Signatures)-1]
	if err := checkForwardDomain(previous, options); err != nil {
		return nil, err
	}
	sig, err := makeSignature(m.Instances, m.Signatures, previous.Index+1, options)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sig)+len(wire))
	out = append(out, sig...)
	out = append(out, wire...)
	return out, nil
}

// ForwardChecked authenticates the incoming message before adding a hop.
// The incoming envelope must be the one used when this message was received.
func ForwardChecked(wire []byte, incoming Envelope, verification VerifyOptions, options SignOptions) ([]byte, error) {
	if err := verifyBeforeForwarding(wire, incoming, verification); err != nil {
		return nil, err
	}
	return forward(wire, options)
}

// Revise signs a modified message under an explicit out-of-band arrangement.
// Otherwise use ReviseChecked to authenticate the original message first.
func Revise(wire []byte, recipeJSON []byte, options SignOptions) ([]byte, error) {
	if !options.OutOfBandArrangement {
		return nil, errors.New("dkim2: Revise requires ReviseChecked or an explicit out-of-band arrangement")
	}
	return revise(wire, recipeJSON, options)
}

// revise records a JSON Recipe that reconstructs the previous instance. The
// input must retain the prior DKIM2 fields. The Recipe is checked against the
// previous hash before a new signature is made.
func revise(wire []byte, recipeJSON []byte, options SignOptions) ([]byte, error) {
	m, err := Parse(wire)
	if err != nil {
		return nil, err
	}
	if err := validateStructure(m); err != nil {
		return nil, err
	}
	options, err = normalizeSignOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateSignOptions(options); err != nil {
		return nil, err
	}
	previousSig := m.Signatures[len(m.Signatures)-1]
	if err := checkForwardDomain(previousSig, options); err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(recipeJSON)
	r, err := parseRecipe(encoded)
	if err != nil {
		return nil, err
	}
	if _, changed := r.Headers["from"]; changed {
		if err := checkAuthenticFrom(m.Headers, options.Domain, options.PolicyResolver); err != nil {
			return nil, err
		}
	}
	nullBody := r.NullBody
	if nullBody {
		if !options.AllowNullBodyRecipe {
			return nil, errors.New("dkim2: null body Recipe requires AllowNullBodyRecipe")
		}
		r.HasBody = false // The preceding body cannot be reconstructed here.
		r.NullBody = false
	}
	previous, err := applyRecipe(m, r)
	if err != nil {
		return nil, err
	}
	if err := checkInstanceHashWithBody(previous, m.Instances[len(m.Instances)-1], !nullBody); err != nil {
		return nil, fmt.Errorf("dkim2: Recipe does not reconstruct previous instance: %w", err)
	}
	algorithm := options.HashAlgorithm
	if algorithm == "" {
		algorithm = "sha256"
	}
	hh, err := headerDigest(m.Headers, algorithm)
	if err != nil {
		return nil, err
	}
	bh, err := bodyDigest(m.Body, algorithm)
	if err != nil {
		return nil, err
	}
	number := len(m.Instances) + 1
	mi := fmt.Sprintf("Message-Instance: m=%d;\r\n\tr=%s;\r\n\th=%s:%s:%s;\r\n", number, foldBase64(encoded), algorithm, foldBase64(hh), foldBase64(bh))
	newInstances := append(append([]Instance(nil), m.Instances...), Instance{Number: number, Raw: mi, Recipe: encoded, Hashes: []HashSet{{algorithm, hh, bh}}})
	sig, err := makeSignature(newInstances, m.Signatures, previousSig.Index+1, options)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sig)+len(mi)+len(wire))
	out = append(out, sig...)
	out = append(out, mi...)
	out = append(out, wire...)
	return out, nil
}

// ReviseChecked authenticates the original message before signing a modified
// copy. The modified copy must retain every prior DKIM2 field byte for byte.
func ReviseChecked(original, modified []byte, incoming Envelope, verification VerifyOptions, recipeJSON []byte, options SignOptions) ([]byte, error) {
	if err := verifyBeforeForwarding(original, incoming, verification); err != nil {
		return nil, err
	}
	before, err := Parse(original)
	if err != nil {
		return nil, err
	}
	after, err := Parse(modified)
	if err != nil {
		return nil, err
	}
	if len(before.Instances) != len(after.Instances) || len(before.Signatures) != len(after.Signatures) {
		return nil, errors.New("dkim2: modified message changed prior DKIM2 fields")
	}
	for i := range before.Instances {
		if before.Instances[i].Raw != after.Instances[i].Raw {
			return nil, errors.New("dkim2: modified message changed prior Message-Instance field")
		}
	}
	for i := range before.Signatures {
		if before.Signatures[i].Raw != after.Signatures[i].Raw {
			return nil, errors.New("dkim2: modified message changed prior DKIM2-Signature field")
		}
	}
	return revise(modified, recipeJSON, options)
}

func verifyBeforeForwarding(wire []byte, incoming Envelope, verification VerifyOptions) error {
	result := Verify(wire, incoming, verification)
	if result.Status == Pass {
		return nil
	}
	if result.Err != nil {
		return fmt.Errorf("dkim2: incoming message verification %s: %w", result.Status, result.Err)
	}
	return fmt.Errorf("dkim2: incoming message verification %s", result.Status)
}

func checkForwardDomain(previous Signature, options SignOptions) error {
	if previous.NextDomain != "" {
		if !strings.EqualFold(previous.NextDomain, options.Domain) {
			return errors.New("dkim2: nd= does not match new signing domain")
		}
	} else {
		domain := pathDomain(options.Envelope.MailFrom)
		matches := recipientDomainMatches(previous.Recipients, domain)
		if options.NextDomain != "" || options.Envelope.MailFrom == "<>" {
			matches = recipientMatchesSigner(previous.Recipients, options.Domain)
		}
		if !matches {
			return errors.New("dkim2: next signer is not covered by the previous RCPT TO")
		}
	}
	return nil
}

func validateSignOptions(o SignOptions) error {
	if !validDomain(o.Domain) || !validDomain(o.Selector) {
		return errors.New("dkim2: invalid domain or selector")
	}
	if o.NextDomain != "" {
		if !validDomain(o.NextDomain) || o.Envelope.MailFrom != "" || len(o.Envelope.RcptTo) != 0 {
			return errors.New("dkim2: nd= requires a domain and no mf=/rt= envelope")
		}
	} else {
		if !validPath(o.Envelope.MailFrom, true) || len(o.Envelope.RcptTo) == 0 {
			return errors.New("dkim2: invalid signing envelope")
		}
		for _, p := range o.Envelope.RcptTo {
			if !validPath(p, false) {
				return errors.New("dkim2: invalid RCPT TO path")
			}
		}
		if d := pathDomain(o.Envelope.MailFrom); d != "" && !domainMatch(d, o.Domain) {
			return errors.New("dkim2: d= does not match MAIL FROM domain")
		}
	}
	if o.HashAlgorithm != "" && o.HashAlgorithm != "sha256" && o.HashAlgorithm != "sha512" {
		return errors.New("dkim2: unsupported hash algorithm")
	}
	if !validNonce(o.Nonce) {
		return errors.New("dkim2: invalid nonce")
	}
	for _, f := range o.Flags {
		if !validTextString(f) {
			return errors.New("dkim2: invalid flag")
		}
	}
	_, err := keyAlgorithm(o.Key)
	return err
}

func normalizeSignOptions(options SignOptions) (SignOptions, error) {
	if options.NextDomain == "" {
		envelope, err := normalizeEnvelope(options.Envelope)
		if err != nil {
			return options, err
		}
		options.Envelope = envelope
	}
	return options, nil
}

func keyAlgorithm(key crypto.Signer) (string, error) {
	if key == nil {
		return "", errors.New("dkim2: nil signing key")
	}
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 1024 || pub.E != 65537 {
			return "", errors.New("dkim2: RSA key must be at least 1024 bits with exponent 65537")
		}
		return "rsa-sha256", nil
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return "", errors.New("dkim2: invalid Ed25519 key")
		}
		return "ed25519-sha256", nil
	case *mldsa44.PublicKey:
		return "mldsa44", nil
	default:
		return "", fmt.Errorf("dkim2: unsupported signing key %T", pub)
	}
}

func makeSignature(instances []Instance, previous []Signature, index int, o SignOptions) (string, error) {
	algo, err := keyAlgorithm(o.Key)
	if err != nil {
		return "", err
	}
	timestamp := o.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	var fields []string
	fields = append(fields, fmt.Sprintf("i=%d", index), fmt.Sprintf("m=%d", instances[len(instances)-1].Number), fmt.Sprintf("t=%d", timestamp.Unix()))
	if o.NextDomain != "" {
		fields = append(fields, "nd="+o.NextDomain)
	} else {
		fields = append(fields, "mf="+foldBase64(base64.StdEncoding.EncodeToString([]byte(o.Envelope.MailFrom))))
		var recipients []string
		for _, p := range o.Envelope.RcptTo {
			recipients = append(recipients, foldBase64(base64.StdEncoding.EncodeToString([]byte(p))))
		}
		fields = append(fields, "rt="+strings.Join(recipients, ","))
	}
	fields = append(fields, "d="+o.Domain)
	if o.Nonce != "" {
		fields = append(fields, "n="+o.Nonce)
	}
	if len(o.Flags) > 0 {
		fields = append(fields, "f="+strings.Join(o.Flags, ","))
	}
	fields = append(fields, "s="+o.Selector+":"+algo+":")
	template := "DKIM2-Signature: " + strings.Join(fields, ";\r\n\t") + ";\r\n"
	input, err := signatureInput(instances, previous, template)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(input)
	var signature []byte
	switch algo {
	case "rsa-sha256":
		signature, err = o.Key.Sign(rand.Reader, hash[:], crypto.SHA256)
	case "ed25519-sha256":
		signature, err = o.Key.Sign(rand.Reader, hash[:], crypto.Hash(0))
	case "mldsa44":
		private, ok := o.Key.(*mldsa44.PrivateKey)
		if !ok {
			return "", errors.New("dkim2: ML-DSA-44 key does not expose context signing")
		}
		signature = make([]byte, mldsa44.SignatureSize)
		err = mldsa44.SignTo(private, input, []byte("DKIM2"), false, signature)
	}
	if err != nil {
		return "", err
	}
	encoded := foldBase64(base64.StdEncoding.EncodeToString(signature))
	return strings.Replace(template, "s="+o.Selector+":"+algo+":;", "s="+o.Selector+":"+algo+":"+encoded+";", 1), nil
}

func foldBase64(s string) string {
	if len(s) <= 64 {
		return s
	}
	var b strings.Builder
	for len(s) > 64 {
		b.WriteString(s[:64])
		b.WriteString("\r\n\t")
		s = s[64:]
	}
	b.WriteString(s)
	return b.String()
}

func signatureInput(instances []Instance, previous []Signature, current string) ([]byte, error) {
	var b strings.Builder
	for _, inst := range instances {
		c, err := canonicalHeader(inst.Raw, true)
		if err != nil {
			return nil, err
		}
		b.WriteString(c)
	}
	for _, sig := range previous {
		c, err := canonicalHeader(sig.Raw, true)
		if err != nil {
			return nil, err
		}
		b.WriteString(c)
	}
	c, err := canonicalHeader(current, true)
	if err != nil {
		return nil, err
	}
	// In the field being checked, only the base64 signature bytes are removed.
	c, err = emptySignatureValues(c)
	if err != nil {
		return nil, err
	}
	b.WriteString(c)
	return []byte(b.String()), nil
}

func emptySignatureValues(canonical string) (string, error) {
	if !strings.HasSuffix(canonical, "\r\n") {
		return "", errors.New("dkim2: signature field lacks CRLF")
	}
	content := strings.TrimSuffix(canonical, "\r\n")
	name, value, ok := strings.Cut(content, ":")
	if !ok || name != "dkim2-signature" {
		return "", errors.New("dkim2: invalid signature field name")
	}
	parts := strings.Split(value, ";")
	found := false
	for i, part := range parts {
		if len(part) >= 2 && strings.EqualFold(part[:2], "s=") {
			if found {
				return "", errors.New("dkim2: duplicate s= tag")
			}
			found = true
			var empty strings.Builder
			for _, group := range strings.Split(part[2:], "|") {
				if empty.Len() > 0 {
					empty.WriteByte('|')
				}
				for j, set := range strings.Split(group, ",") {
					if j > 0 {
						empty.WriteByte(',')
					}
					triplet := strings.Split(set, ":")
					if len(triplet) != 3 {
						return "", errors.New("dkim2: malformed s= signature set")
					}
					empty.WriteString(triplet[0] + ":" + triplet[1] + ":")
				}
			}
			parts[i] = part[:2] + empty.String()
		}
	}
	if !found {
		return "", errors.New("dkim2: missing s= tag")
	}
	return name + ":" + strings.Join(parts, ";") + "\r\n", nil
}
