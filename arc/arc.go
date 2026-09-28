package arc

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
)

// 正規化
type Canonicalization canonical.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// ARC署名のアルゴリズム
type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA_SHA1       SignatureAlgorithm = "rsa-sha1"
	SignatureAlgorithmRSA_SHA256     SignatureAlgorithm = "rsa-sha256"
	SignatureAlgorithmED25519_SHA256 SignatureAlgorithm = "ed25519-sha256"
)

type CanonicalizationAndAlgorithm struct {
	Header    Canonicalization
	Body      Canonicalization
	Algorithm SignatureAlgorithm
	HashAlgo  crypto.Hash
}

type VerifyStatus string

const (
	VerifyStatusNeutral VerifyStatus = "neutral"
	VerifyStatusFail    VerifyStatus = "fail"
	VerifyStatusTempErr VerifyStatus = "temperror"
	VerifyStatusPermErr VerifyStatus = "permerror"
	VerifyStatusPass    VerifyStatus = "pass"
	VerifyStatusNone    VerifyStatus = "none"
)

type VerifyResult struct {
	status    VerifyStatus
	err       error
	msg       string
	domainKey *domainkey.DomainKey
}

func (v *VerifyResult) Status() VerifyStatus {
	return v.status
}
func (v *VerifyResult) Error() error {
	return v.err
}
func (v *VerifyResult) Message() string {
	return v.msg
}

type ChainValidationResult string

const (
	ChainValidationResultPass ChainValidationResult = "pass"
	ChainValidationResultFail ChainValidationResult = "fail"
	ChainValidationResultNone ChainValidationResult = "none"
)

func isChainValidationResult(s string) bool {
	switch ChainValidationResult(s) {
	case ChainValidationResultPass, ChainValidationResultFail, ChainValidationResultNone:
		return true
	default:
		return false
	}
}

type Signature struct {
	instanceNumber           int
	arcSeal                  *ARCSeal
	arcMessageSignature      *ARCMessageSignature
	arcAuthenticationResults *ARCAuthenticationResults
	VerifyResult             *VerifyResult
	sealResult               *VerifyResult
	messageResult            *VerifyResult
	parseErr                 error
}

func (arc *Signature) GetInstanceNumber() int {
	return arc.instanceNumber
}

func (arc *Signature) GetARCSeal() *ARCSeal {
	return arc.arcSeal
}

func (arc *Signature) GetARCMessageSignature() *ARCMessageSignature {
	return arc.arcMessageSignature
}

func (arc *Signature) GetARCAuthenticationResults() *ARCAuthenticationResults {
	return arc.arcAuthenticationResults
}

func (arc *Signature) GetVerifyResult() *VerifyResult {
	return arc.VerifyResult
}

// Verify checks a set. A non-nil domainKey overrides both keys for compatibility.
// With nil, AS and AMS each resolve their own selector and domain.
func (arc *Signature) Verify(headers []string, bodyHash string, domainKey *domainkey.DomainKey) {
	arc.VerifyWithKeys(headers, bodyHash, domainKey, domainKey)
}

// VerifyWithKeys allows separate AS and AMS keys; nil keys are resolved by DNS.
func (arc *Signature) VerifyWithKeys(headers []string, bodyHash string, sealKey, messageKey *domainkey.DomainKey) {
	if arc == nil {
		return
	}
	if arc.parseErr != nil {
		arc.VerifyResult = &VerifyResult{status: VerifyStatusFail, err: arc.parseErr, msg: "malformed ARC headers"}
		return
	}
	arc.sealResult, arc.messageResult = nil, nil
	if arc.arcSeal == nil || arc.arcMessageSignature == nil || arc.arcAuthenticationResults == nil {
		arc.VerifyResult = &VerifyResult{status: VerifyStatusFail, err: fmt.Errorf("ARC set is incomplete"), msg: "ARC set is incomplete"}
		return
	}
	arc.sealResult = arc.arcSeal.Verify(headers, sealKey)
	arc.messageResult = arc.arcMessageSignature.Verify(headers, bodyHash, messageKey)
	arc.VerifyResult = arc.sealResult
	if arc.sealResult.status == VerifyStatusPass {
		arc.VerifyResult = arc.messageResult
	}
}

func hashAlgo(algo SignatureAlgorithm) crypto.Hash {
	switch algo {
	case SignatureAlgorithmRSA_SHA1:
		return crypto.SHA1
	case SignatureAlgorithmRSA_SHA256:
		return crypto.SHA256
	case SignatureAlgorithmED25519_SHA256:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
