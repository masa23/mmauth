package arc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/masa23/mmauth/internal/header"
)

type Signatures []*Signature

// インスタンス番号を指定してSignatureを取得する
func (s *Signatures) GetInstance(i int) *Signature {
	if s == nil {
		return nil
	}
	for _, sig := range *s {
		if sig != nil && sig.instanceNumber == i {
			return sig
		}
	}
	sig := &Signature{
		instanceNumber: i,
	}
	*s = append(*s, sig)
	return sig
}

// 最大のインスタンス番号を取得する
func (s *Signatures) GetMaxInstance() int {
	if s == nil {
		return 0
	}
	max := 0
	for _, sig := range *s {
		if sig != nil && sig.GetInstanceNumber() > max {
			max = sig.GetInstanceNumber()
		}
	}
	return max
}

// GetVerifyResultString reports the validation status of the entire chain.
func (s *Signatures) GetVerifyResultString() string {
	status := s.GetVerifyResult()
	if status == VerifyStatusNone {
		return "arc=none"
	}
	for _, sig := range *s {
		if sig != nil && sig.parseErr != nil {
			return "arc=fail (malformed ARC headers)"
		}
	}
	return fmt.Sprintf("arc=%s (i=%d)", status, s.GetMaxInstance())
}

// GetVerifyResult requires all seals and the latest AMS to pass. A historical
// AMS failure is expected after forwarding and does not invalidate the chain.
func (s *Signatures) GetVerifyResult() VerifyStatus {
	if s == nil || len(*s) == 0 {
		return VerifyStatusNone
	}
	for _, sig := range *s {
		if sig != nil && sig.parseErr != nil {
			return VerifyStatusFail
		}
	}
	if err := s.validateStructure(true); err != nil {
		return VerifyStatusFail
	}
	max := s.GetMaxInstance()
	unverified := false
	for _, sig := range *s {
		if sig.sealResult == nil {
			unverified = true
		} else if sig.sealResult.Status() != VerifyStatusPass {
			return VerifyStatusFail
		}
		if sig.instanceNumber == max {
			if sig.messageResult == nil {
				unverified = true
			} else if sig.messageResult.Status() != VerifyStatusPass {
				return VerifyStatusFail
			}
		}
	}
	if unverified {
		return VerifyStatusNone
	}
	return VerifyStatusPass
}

// GetARCChainValidation returns none for a structurally valid, unverified chain.
// Claimed cv= values alone are never treated as proof of a valid chain.
func (s *Signatures) GetARCChainValidation() ChainValidationResult {
	switch s.GetVerifyResult() {
	case VerifyStatusPass:
		return ChainValidationResultPass
	case VerifyStatusNone:
		return ChainValidationResultNone
	default:
		return ChainValidationResultFail
	}
}

func (s *Signatures) validateStructure(checkCV bool) error {
	if s == nil {
		return nil
	}
	max := s.GetMaxInstance()
	if len(*s) != max || max > 50 {
		return fmt.Errorf("ARC instances must be continuous from 1 to at most 50")
	}
	seen := make(map[int]bool)
	for _, sig := range *s {
		if sig == nil || sig.instanceNumber < 1 || sig.instanceNumber > 50 {
			return fmt.Errorf("invalid ARC instance")
		}
		if seen[sig.instanceNumber] {
			return fmt.Errorf("duplicate ARC instance")
		}
		seen[sig.instanceNumber] = true
		if sig.arcSeal == nil || sig.arcAuthenticationResults == nil || sig.arcMessageSignature == nil {
			return fmt.Errorf("arc headers are missing")
		}
		if checkCV {
			want := ChainValidationResultPass
			if sig.instanceNumber == 1 {
				want = ChainValidationResultNone
			}
			if sig.arcSeal.invalid || sig.arcSeal.ChainValidation != want {
				return fmt.Errorf("invalid ARC cv at instance %d", sig.instanceNumber)
			}
		}
	}
	return nil
}

// ParseARCHeaders requires one AAR, AMS and AS per consecutive instance.
// On error it returns a failed chain as well as the error, so callers that
// continue other authentication checks cannot mistake malformed ARC for none.
// The failed chain retains the largest recognizable instance in the 1..50 range;
// it is a failure marker, not a partially usable set of ARC headers.
func ParseARCHeaders(headers []string) (*Signatures, error) {
	parsed, err := parseARCHeaders(headers)
	if err != nil {
		return failedARCHeaders(headers, err), err
	}
	sigs := Signatures(*parsed)
	if err := sigs.validateStructure(false); err != nil {
		return failedARCHeaders(headers, err), err
	}
	return &sigs, nil
}

// arcHeaderInstance reads only the instance tag, without requiring other tags
// to parse. This lets failure sealing ignore malformed historical sets.
func arcHeaderInstance(raw string) (int, bool) {
	name, value := header.ParseHeaderField(raw)
	switch strings.ToLower(name) {
	case "arc-seal", "arc-message-signature", "arc-authentication-results":
	default:
		return 0, false
	}
	for _, field := range strings.Split(value, ";") {
		key, value, ok := strings.Cut(field, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "i") {
			n, err := strconv.Atoi(header.StripWhiteSpace(value))
			return n, err == nil
		}
	}
	return 0, false
}

func failedARCHeaders(headers []string, err error) *Signatures {
	max := 0
	for _, raw := range headers {
		if n, ok := arcHeaderInstance(raw); ok && n > max && n <= 50 {
			max = n
		}
	}
	return &Signatures{&Signature{
		instanceNumber: max, parseErr: err,
		VerifyResult: &VerifyResult{status: VerifyStatusFail, err: err, msg: "malformed ARC headers"},
	}}
}

// ARCヘッダをSealで署名する順番にソートする
func (s *Signatures) GetARCHeaders() []string {
	if s == nil {
		return nil
	}
	var ret []string
	max := s.GetMaxInstance()
	if max <= 0 {
		return ret
	}

	for i := 1; i <= max; i++ {
		arc := s.GetInstance(i)
		if arc != nil && arc.arcAuthenticationResults != nil && arc.arcMessageSignature != nil && arc.arcSeal != nil {
			ret = append(ret, arc.arcAuthenticationResults.Raw())
			ret = append(ret, arc.arcMessageSignature.Raw())
			ret = append(ret, arc.arcSeal.Raw())
		}
	}
	return ret
}
