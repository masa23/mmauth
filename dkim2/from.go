package dkim2

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/masa23/mmauth/domainkey"
)

func fromDomain(headers []string) (string, error) {
	var raw string
	for _, field := range headers {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, "From") {
			if raw != "" {
				return "", errors.New("dkim2: more than one From field")
			}
			raw = field
		}
	}
	if raw == "" {
		return "", errors.New("dkim2: From field missing")
	}
	unfolded, err := unfold(raw)
	if err != nil {
		return "", err
	}
	_, value, _ := strings.Cut(unfolded, ":")
	if hasUnquotedSemicolon(value) {
		return "", errors.New("dkim2: From uses a group instead of a mailbox")
	}
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) != 1 {
		return "", errors.New("dkim2: From must contain exactly one address")
	}
	at := strings.LastIndexByte(addresses[0].Address, '@')
	if at < 0 {
		return "", errors.New("dkim2: From address has no domain")
	}
	domain := addresses[0].Address[at+1:]
	if strings.HasPrefix(domain, "[") {
		return "", errors.New("dkim2: From uses a domain literal or invalid domain")
	}
	return asciiDomain(domain)
}

func hasUnquotedSemicolon(value string) bool {
	quoted, escaped, comments := false, false, 0
	for _, c := range value {
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && (quoted || comments > 0) {
			escaped = true
			continue
		}
		if c == '"' && comments == 0 {
			quoted = !quoted
			continue
		}
		if !quoted {
			if c == '(' {
				comments++
			} else if c == ')' && comments > 0 {
				comments--
			} else if c == ';' && comments == 0 {
				return true
			}
		}
	}
	return false
}

func checkAuthenticFrom(headers []string, signingDomain string, resolver domainkey.TXTResolver) error {
	domain, err := fromDomain(headers)
	if err != nil {
		return err
	}
	if domainMatch(domain, signingDomain) {
		return nil
	}
	if !domainMatch(signingDomain, domain) {
		return fmt.Errorf("dkim2: From %s is not authentic for %s", domain, signingDomain)
	}
	if resolver == nil {
		resolver = domainkey.NewDefaultTXTResolver()
	}
	strict, err := lookupStrictPolicy(resolver, domain)
	if err != nil {
		return err
	}
	if strict {
		return fmt.Errorf("dkim2: From %s forbids subdomain signing by %s", domain, signingDomain)
	}
	return nil
}

func fromErrorStatus(err error) Status {
	var temporary *temporaryDNSError
	if errors.As(err, &temporary) {
		return TempError
	}
	var permanent *permanentKeyError
	if errors.As(err, &permanent) {
		return PermError
	}
	return Fail
}
