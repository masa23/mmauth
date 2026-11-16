package dkim2

import (
	"errors"
	"fmt"
	"strings"
)

// DSNPropagationOptions identifies the outward message as it arrived at this
// forwarder, before its signatures were added. The caller must retain that
// receipt-time signature index; inferring it from a domain could erase an
// earlier hop operated by the same organization.
type DSNPropagationOptions struct {
	Verification           DSNVerifyOptions
	Notification           DSNOptions
	ReceivedSignatureIndex int
}

// PropagateDSN authenticates an incoming DSN, undoes this forwarder's outward
// revisions, and builds a newly signed DSN addressed to the preceding MAIL
// FROM. New human text and recipient status must be supplied in Notification;
// the downstream report's first two MIME parts are never copied upstream.
// It returns bytes and an envelope without transmitting anything.
func PropagateDSN(wire []byte, envelope Envelope, options DSNPropagationOptions) (*GeneratedDSN, error) {
	// Reuse the same total DNS budget during all authentication in this call.
	verification, err := dsnVerificationOptions(options.Verification)
	if err != nil {
		return nil, err
	}
	verifyOptions := options.Verification
	verifyOptions.Verification = verification
	result := VerifyDSN(wire, envelope, verifyOptions)
	if result.Status != Pass {
		if result.Err != nil {
			return nil, fmt.Errorf("dkim2: DSN cannot be propagated (%s): %w", result.Status, result.Err)
		}
		return nil, fmt.Errorf("dkim2: DSN cannot be propagated (%s)", result.Status)
	}
	m, err := Parse(result.Original)
	if err != nil {
		return nil, err
	}
	if err := validateStructure(m); err != nil {
		return nil, fmt.Errorf("dkim2: cannot reconstruct DSN history: %w", err)
	}
	cutoff := options.ReceivedSignatureIndex
	if cutoff < 1 || cutoff >= len(m.Signatures) {
		return nil, errors.New("dkim2: invalid receipt-time signature index")
	}
	for _, signature := range m.Signatures[cutoff:] {
		if !localSigningDomain(signature.Domain, options.Verification.LocalDomains) {
			return nil, errors.New("dkim2: cannot remove another system's outward signature")
		}
	}
	previous := m.Signatures[cutoff-1]
	if previous.NextDomain != "" || previous.MailFrom == "<>" {
		return nil, errors.New("dkim2: previous hop has no standard DSN return path")
	}
	if !recipientMatchesSigner(previous.Recipients, options.Notification.Sign.Domain) {
		return nil, errors.New("dkim2: propagating DSN signer does not match the previous recipients")
	}
	original, headersOnly, err := restoreDSNOriginal(m, cutoff, result.HeadersOnly)
	if err != nil {
		return nil, err
	}
	restored, err := Parse(original)
	if err != nil {
		return nil, err
	}
	// Authenticate the return path again: an outer local signature alone does
	// not establish the legitimacy of a predecessor's MAIL FROM.
	if err := authenticateDSNOriginal(restored, headersOnly, []string{previous.Domain}, verification); err != nil {
		return nil, fmt.Errorf("dkim2: previous hop is not authenticated: %w", err)
	}
	notification := options.Notification
	notification.HeadersOnly = notification.HeadersOnly || headersOnly
	for _, recipient := range notification.Recipients {
		normalized, err := normalizePath(recipient.FinalRecipient)
		if err != nil {
			return nil, err
		}
		found := false
		for _, recorded := range previous.Recipients {
			if equalPath(normalized, recorded) {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("dkim2: upstream report exposes a downstream recipient")
		}
	}
	return buildDSN(original, Envelope{MailFrom: "<>", RcptTo: []string{previous.MailFrom}}, notification)
}

func restoreDSNOriginal(m *Message, cutoff int, headersOnly bool) ([]byte, bool, error) {
	target := m.Signatures[cutoff-1].Instance
	state := m
	if headersOnly {
		state = &Message{Headers: m.Headers}
	}
	for i := len(m.Instances) - 1; i >= target; i-- {
		instance := m.Instances[i]
		if instance.Recipe != "" {
			r, err := parseRecipe(instance.Recipe)
			if err != nil {
				return nil, false, err
			}
			if r.NullBody {
				headersOnly = true
			}
			if headersOnly {
				state = &Message{Headers: state.Headers}
				r.HasBody, r.NullBody = false, false
			}
			state, err = applyRecipe(state, r)
			if err != nil {
				return nil, false, err
			}
		}
		if err := checkInstanceHashWithBody(state, m.Instances[i-1], !headersOnly); err != nil {
			return nil, false, fmt.Errorf("dkim2: DSN cannot restore prior instance: %w", err)
		}
	}
	var out strings.Builder
	for _, field := range state.Headers {
		name, _, _ := strings.Cut(field, ":")
		switch strings.ToLower(name) {
		case "dkim2-signature":
			sig, err := parseSignature(field)
			if err != nil {
				return nil, false, err
			}
			if sig.Index > cutoff {
				continue
			}
		case "message-instance":
			inst, err := parseInstance(field)
			if err != nil {
				return nil, false, err
			}
			if inst.Number > target {
				continue
			}
		default:
			// Remove all unsigned trace/extension fields: they cannot be
			// authenticated as belonging to the receipt-time message and may
			// disclose downstream routing (section 16.3's good-faith cleanup).
			if unsigned(strings.ToLower(name)) {
				continue
			}
		}
		out.WriteString(field)
	}
	if !headersOnly {
		out.WriteString("\r\n")
		out.Write(state.Body)
	}
	if out.Len() > maxMessageBytes {
		return nil, false, errors.New("dkim2: restored DSN original exceeds message limit")
	}
	return []byte(out.String()), headersOnly, nil
}
