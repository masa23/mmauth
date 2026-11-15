package dkim2

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

func asciiDomain(domain string) (string, error) {
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil || !validDomain(ascii) {
		return "", errors.New("dkim2: invalid internationalized domain")
	}
	return ascii, nil
}

// normalizePath maps U-labels to A-labels while leaving the local part
// unchanged. The mapped path is the one recorded in mf= or rt=.
func normalizePath(path string) (string, error) {
	if path == "<>" {
		return path, nil
	}
	if len(path) < 3 || path[0] != '<' || path[len(path)-1] != '>' || strings.ContainsAny(path, "\r\n\x00") {
		return "", errors.New("dkim2: invalid SMTP path")
	}
	if strings.EqualFold(path, "<Postmaster>") {
		return path, nil
	}
	inner := path[1 : len(path)-1]
	route := ""
	if strings.HasPrefix(inner, "@") {
		prefix, mailbox, ok := strings.Cut(inner, ":")
		if !ok {
			return "", errors.New("dkim2: invalid SMTP source route")
		}
		var parts []string
		for _, part := range strings.Split(prefix, ",") {
			if len(part) < 2 || part[0] != '@' {
				return "", errors.New("dkim2: invalid SMTP source route")
			}
			domain, err := asciiDomain(part[1:])
			if err != nil {
				return "", err
			}
			parts = append(parts, "@"+domain)
		}
		route = strings.Join(parts, ",") + ":"
		inner = mailbox
	}
	at := strings.LastIndexByte(inner, '@')
	if at <= 0 {
		return "", errors.New("dkim2: SMTP path has no mailbox domain")
	}
	domain := inner[at+1:]
	if !strings.HasPrefix(domain, "[") {
		var err error
		domain, err = asciiDomain(domain)
		if err != nil {
			return "", err
		}
	}
	normalized := "<" + route + inner[:at+1] + domain + ">"
	if !validPath(normalized, true) {
		return "", errors.New("dkim2: invalid SMTP path")
	}
	return normalized, nil
}

func normalizeEnvelope(envelope Envelope) (Envelope, error) {
	mailFrom, err := normalizePath(envelope.MailFrom)
	if err != nil {
		return Envelope{}, err
	}
	result := Envelope{MailFrom: mailFrom}
	for _, path := range envelope.RcptTo {
		normalized, err := normalizePath(path)
		if err != nil {
			return Envelope{}, err
		}
		result.RcptTo = append(result.RcptTo, normalized)
	}
	return result, nil
}
