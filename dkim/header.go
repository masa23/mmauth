package dkim

import (
	"fmt"
	"strings"

	"github.com/masa23/mmauth/internal/header"
)

type Signatures []*Signature

func (d *Signatures) GetResult() VerifyStatus {
	// DKIM署名がない場合はNone
	if d == nil {
		return VerifyStatusNone
	}
	if len(*d) == 0 {
		return VerifyStatusNone
	}
	for _, sig := range *d {
		if sig == nil || sig.VerifyResult == nil {
			return VerifyStatusNone
		}
		if sig.VerifyResult.Status() != VerifyStatusPass {
			return sig.VerifyResult.Status()
		}
	}
	return VerifyStatusPass
}

// ParseDKIMHeaders preserves malformed signatures with a permerror result so
// that other signatures can still be verified. ParseSignature remains strict.
func ParseDKIMHeaders(headers []string) (*Signatures, error) {
	var sigs Signatures
	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "dkim-signature":
			sig, err := ParseSignature(h)
			if err != nil {
				parseErr := fmt.Errorf("failed to parse dkim-signature: %w", err)
				sig = &Signature{raw: h, parseErr: parseErr, VerifyResult: &VerifyResult{status: VerifyStatusPermErr, err: parseErr, msg: "malformed signature"}}
			}
			sigs = append(sigs, sig)
		}
	}
	return &sigs, nil
}
