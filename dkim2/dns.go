package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/masa23/mmauth/domainkey"
)

// selectTXTRecord implements the version filtering shared by key and policy
// records. Other versions coexist at a DNS name and are ignored.
func selectTXTRecord(records []string, requireVersion bool) (string, error) {
	var selected string
	for _, raw := range records {
		first := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		name, value, hasTag := strings.Cut(first, "=")
		if hasTag && strings.EqualFold(strings.TrimSpace(name), "v") && strings.TrimSpace(value) != "DKIM1" {
			continue
		}
		if requireVersion && (!hasTag || !strings.EqualFold(strings.TrimSpace(name), "v")) {
			continue
		}
		if selected != "" {
			return "", errors.New("multiple DKIM1 TXT records")
		}
		selected = raw
	}
	return selected, nil
}

func parseTXTTags(raw string) (map[string]string, error) {
	unfolded, err := unfold("TXT:" + raw + "\r\n")
	if err != nil {
		return nil, err
	}
	_, unfolded, _ = strings.Cut(unfolded, ":")
	tags := make(map[string]string)
	parts := strings.Split(unfolded, ";")
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if index != len(parts)-1 {
				return nil, errors.New("empty DNS tag between semicolons")
			}
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !validTag(name) {
			return nil, errors.New("malformed or duplicate DNS tag")
		}
		if _, exists := tags[name]; exists {
			return nil, errors.New("duplicate DNS tag")
		}
		tags[name] = strings.TrimSpace(value)
	}
	return tags, nil
}

func lookupTXT(resolver domainkey.TXTResolver, name string, missingOK bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if missingOK {
				return "", nil
			}
			return "", &permanentKeyError{fmt.Errorf("dkim2: %s does not exist: %w", name, err)}
		}
		return "", &temporaryDNSError{fmt.Errorf("dkim2: %s lookup failed: %w", name, err)}
	}
	selected, err := selectTXTRecord(records, missingOK)
	if err != nil {
		return "", &permanentKeyError{fmt.Errorf("dkim2: %s: %w", name, err)}
	}
	if selected == "" && !missingOK {
		return "", &permanentKeyError{fmt.Errorf("dkim2: %s has no usable DKIM1 key", name)}
	}
	return selected, nil
}

func lookupKey(resolver domainkey.TXTResolver, domain, selector, algorithm string) (keyData, error) {
	name := selector + "._domainkey." + domain
	raw, err := lookupTXT(resolver, name, false)
	if err != nil {
		return keyData{}, err
	}
	tags, err := parseTXTTags(raw)
	if err != nil {
		return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s: %w", name, err)}
	}
	if version, ok := tags["v"]; ok {
		first := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		if version != "DKIM1" || !strings.HasPrefix(strings.ToLower(first), "v") {
			return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: invalid key version at %s", name)}
		}
	}
	encoded, ok := tags["p"]
	if !ok || encoded == "" {
		return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: missing or revoked key %s", name)}
	}
	keyType := tags["k"]
	if keyType == "" {
		keyType = "rsa"
	}
	want := map[string]string{"rsa-sha256": "rsa", "ed25519-sha256": "ed25519", "mldsa44": "mldsa44"}[algorithm]
	if keyType != want {
		return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s algorithm mismatch", name)}
	}
	decoded, err := b64(encoded)
	if err != nil {
		return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s invalid p=: %w", name, err)}
	}
	switch keyType {
	case "ed25519":
		if len(decoded) != ed25519.PublicKeySize {
			return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s invalid Ed25519 length", name)}
		}
		return keyData{public: ed25519.PublicKey(decoded)}, nil
	case "mldsa44":
		var pub mldsa44.PublicKey
		if err := pub.UnmarshalBinary(decoded); err != nil {
			return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s invalid ML-DSA-44 length: %w", name, err)}
		}
		return keyData{public: &pub}, nil
	case "rsa":
		pub, err := x509.ParsePKCS1PublicKey(decoded)
		if err != nil {
			var parsed any
			parsed, err = x509.ParsePKIXPublicKey(decoded)
			pub, _ = parsed.(*rsa.PublicKey)
		}
		if err != nil || pub == nil {
			return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s invalid RSA public key", name)}
		}
		return keyData{public: pub}, nil
	}
	return keyData{}, &permanentKeyError{fmt.Errorf("dkim2: key %s unsupported type", name)}
}

func lookupStrictPolicy(resolver domainkey.TXTResolver, domain string) (bool, error) {
	name := "_domainkey." + domain
	raw, err := lookupTXT(resolver, name, true)
	if err != nil || raw == "" {
		return false, err
	}
	tags, err := parseTXTTags(raw)
	if err != nil || tags["v"] != "DKIM1" {
		return false, &permanentKeyError{fmt.Errorf("dkim2: invalid domain policy at %s: %v", name, err)}
	}
	for _, flag := range strings.Split(tags["f"], ":") {
		if strings.TrimSpace(flag) == "strict" {
			return true, nil
		}
	}
	return false, nil
}
