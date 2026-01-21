package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/header"
)

// ARC-Message-Signature の構造体
type ARCMessageSignature struct {
	Algorithm        SignatureAlgorithm // a algorithm
	Signature        string             // b signature
	BodyHash         string             // bh body hash
	Canonicalization string             // c canonicalization
	Domain           string             // d domain
	Headers          string             // h headers
	InstanceNumber   int                // i instance number
	Selector         string             // s selector
	Timestamp        int64              // t timestamp
	raw              string
	canonnAndAlgo    *CanonicalizationAndAlgorithm
}

func (ams *ARCMessageSignature) Raw() string {
	if ams.raw == "" {
		return ams.String()
	}
	return ams.raw
}

func (ams *ARCMessageSignature) GetCanonicalizationAndAlgorithm() *CanonicalizationAndAlgorithm {
	return ams.canonnAndAlgo
}

// ARC-Message-Signature の文字列化
// ヘッダ名は含まない
func (ams ARCMessageSignature) String() string {
	// format: i=1; a=rsa-sha256; d=example.com; s=selector; t=1234567890; h=from:to:subject; b=MIIBI...
	return fmt.Sprintf("i=%d; a=%s; c=%s; d=%s; s=%s;\r\n"+
		"        h=%s;\r\n"+
		"        bh=%s; t=%d;\r\n"+
		"        b=%s",
		ams.InstanceNumber, ams.Algorithm, ams.Canonicalization, ams.Domain, ams.Selector,
		ams.Headers,
		ams.BodyHash, ams.Timestamp,
		header.WrapSignatureWithBreaks(ams.Signature),
	)
}

// ARC-Message-Signature のパース
func ParseARCMessageSignature(s string) (*ARCMessageSignature, error) {
	result := &ARCMessageSignature{}
	result.raw = s

	// ヘッダと値に分割
	k, v := header.ParseHeaderField(s)
	if !strings.EqualFold(k, "arc-message-signature") {
		return nil, fmt.Errorf("invalid header field")
	}
	fields := strings.Split(v, ";")

	for _, field := range fields {
		keyValue := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(keyValue[0]))
		value := header.StripWhiteSpace(keyValue[1])

		switch key {
		case "i":
			instanceNumber, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid instance number")
			}
			result.InstanceNumber = instanceNumber
		case "a":
			switch SignatureAlgorithm(value) {
			case SignatureAlgorithmRSA_SHA1:
				result.Algorithm = SignatureAlgorithmRSA_SHA1
			case SignatureAlgorithmRSA_SHA256:
				result.Algorithm = SignatureAlgorithmRSA_SHA256
			case SignatureAlgorithmED25519_SHA256:
				result.Algorithm = SignatureAlgorithmED25519_SHA256
			default:
				return nil, fmt.Errorf("invalid algorithm")
			}
		case "b":
			// valueから改行と空白を削除
			value = strings.ReplaceAll(value, "\r\n", "")
			value = strings.ReplaceAll(value, " ", "")
			result.Signature = value
		case "d":
			result.Domain = value
		case "s":
			result.Selector = value
		case "t":
			timestamp, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp")
			}
			result.Timestamp = timestamp
		case "c":
			result.Canonicalization = value
		case "bh":
			result.BodyHash = value
		case "h":
			result.Headers = value
		}
	}

	canHeader, canBody, err := header.ParseHeaderCanonicalization(result.Canonicalization)
	if err != nil {
		return nil, err
	}
	result.canonnAndAlgo = &CanonicalizationAndAlgorithm{
		Header:    Canonicalization(canHeader),
		Body:      Canonicalization(canBody),
		Algorithm: result.Algorithm,
		HashAlgo:  hashAlgo(result.Algorithm),
	}

	return result, nil
}

// ARC-Message-Signature の署名
func (ams *ARCMessageSignature) Sign(headers []string, key crypto.Signer) error {
	// RFC 8617で禁止されるヘッダを定義
	forbiddenHeaders := map[string]bool{
		"authentication-results":     true,
		"arc-authentication-results": true,
		"arc-message-signature":      true,
		"arc-seal":                   true,
	}

	// headersのヘッダ名を抽出し、禁止ヘッダを除外
	var h []string
	for _, header := range headers {
		k, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		// 小文字に正規化して比較
		lowerK := strings.ToLower(strings.TrimSpace(k))
		if forbiddenHeaders[lowerK] {
			continue
		}
		h = append(h, k)
	}
	h = header.RemoveDuplicates(h)
	canHeader, _, err := header.ParseHeaderCanonicalization(ams.Canonicalization)
	if err != nil {
		return err
	}

	// 署名アルゴリズムが指定されていない場合は鍵のタイプから自動設定
	if ams.Algorithm == "" {
		switch key.Public().(type) {
		case *rsa.PublicKey:
			ams.Algorithm = SignatureAlgorithmRSA_SHA256
		case ed25519.PublicKey:
			ams.Algorithm = SignatureAlgorithmED25519_SHA256
		default:
			return fmt.Errorf("unknown key type: %T", key.Public())
		}
	}

	ams.Headers = strings.Join(h, ":")

	// timestampを設定
	if ams.Timestamp == 0 {
		ams.Timestamp = time.Now().Unix()
	}

	// ams.canonnAndAlgo が未初期化の場合に初期化処理を追加
	if ams.canonnAndAlgo == nil {
		canHeaderCanon, canBodyCanon, err := header.ParseHeaderCanonicalization(ams.Canonicalization)
		if err != nil {
			return fmt.Errorf("failed to parse canonicalization: %w", err)
		}
		ams.canonnAndAlgo = &CanonicalizationAndAlgorithm{
			Header:    Canonicalization(canHeaderCanon),
			Body:      Canonicalization(canBodyCanon),
			Algorithm: ams.Algorithm,
			HashAlgo:  hashAlgo(ams.Algorithm),
		}
	}

	// h= タグに指定されたヘッダ名の順序でヘッダを抽出
	headerNames := strings.Split(ams.Headers, ":")
	signingHeaders := make([]string, 0, len(headerNames)+1)
	for _, name := range headerNames {
		for _, header := range headers {
			k, _, ok := strings.Cut(header, ":")
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(name)) {
				signingHeaders = append(signingHeaders, header)
				break
			}
		}
	}

	// RFC 5322 header fields are terminated with CRLF. Ensure the signature header
	// we add to the signing set is also CRLF-terminated so header canonicalization
	// behaves consistently (especially for simple header canonicalization).
	// AMSヘッダは署名対象に含めない

	signature, err := header.Signer(signingHeaders, key, canonical.Canonicalization(canHeader), ams.canonnAndAlgo.HashAlgo)
	if err != nil {
		return err
	}
	ams.Signature = signature
	return nil
}

// ARC-Message-Signature の検証
func (ams *ARCMessageSignature) Verify(headers []string, bodyHash string, domainKey *domainkey.DomainKey) *VerifyResult {
	// h= に含まれてはいけないヘッダをチェック
	forbiddenHeaders := map[string]bool{
		"authentication-results":     true,
		"arc-authentication-results": true,
		"arc-message-signature":      true,
		"arc-seal":                   true,
	}

	for _, headerName := range strings.Split(ams.Headers, ":") {
		normalized := strings.ToLower(strings.TrimSpace(headerName))
		if forbiddenHeaders[normalized] {
			return &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("ARC-Message-Signature header field contains forbidden header: %s", normalized),
				msg:    fmt.Sprintf("forbidden header %s found in h= tag", normalized),
			}
		}
	}

	// domainKeyがnilの場合はLookupDomainKeyを実行
	if domainKey == nil {
		domKey, err := domainkey.LookupARCDomainKey(ams.Selector, ams.Domain)
		if errors.Is(err, domainkey.ErrNoRecordFound) {
			return &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("domain key is not found: %v", err),
				msg:    "domain key is not found",
			}
		} else if err != nil {
			return &VerifyResult{
				status: VerifyStatusTempErr,
				err:    fmt.Errorf("failed to lookup domain key: %v", err),
				msg:    "failed to lookup domain key",
			}
		}
		domainKey = &domKey
	}

	if ams.raw == "" {
		return &VerifyResult{
			status:    VerifyStatusNeutral,
			err:       fmt.Errorf("arc message signature is not found"),
			msg:       "sign is not found",
			domainKey: domainKey,
		}
	}

	// ボディハッシュの検証
	if ams.BodyHash != bodyHash {
		return &VerifyResult{
			status:    VerifyStatusFail,
			err:       fmt.Errorf("ARC-Message-Signature body hash is not match: %s != %s", ams.BodyHash, bodyHash),
			msg:       "body hash is not match",
			domainKey: domainKey,
		}
	}

	// ヘッダの抽出と連結
	// ヘッダ名を抽出して比較するよう統一する
	// AMSヘッダをヘッダリストから削除
	filteredHeaders := make([]string, 0, len(headers))
	for _, header := range headers {
		k, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), "ARC-Message-Signature") {
			filteredHeaders = append(filteredHeaders, header)
		}
	}
	// h= タグに指定されたヘッダ名の順序でヘッダを抽出
	headerNames := strings.Split(ams.Headers, ":")
	h := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		for _, header := range filteredHeaders {
			k, _, ok := strings.Cut(header, ":")
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(name)) {
				h = append(h, header)
				break
			}
		}
	}

	// ARC-Message-Signatureヘッダを再構築 (b=タグは空)
	amsForSigning := *ams
	amsForSigning.Signature = ""
	//amsHeaderForSigning := "ARC-Message-Signature: " + amsForSigning.String() + "\r\n"
	//amsHeaderForSigningRaw := "ARC-Message-Signature: " + amsForSigning.String() + "\r\n"
	//amsHeaderForSigning := canonical.Header(amsHeaderForSigningRaw, canonical.Canonicalization(ams.canonnAndAlgo.Header))

	// ヘッダの正規化
	var s string
	for _, header := range h {
		// h=ARC-Sealがある場合はエラー
		// ヘッダ名を抽出して比較するよう統一する
		k, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "ARC-Seal") {
			return &VerifyResult{
				status:    VerifyStatusPermErr,
				err:       fmt.Errorf("ARC-Message-Signature header field contains ARC-Seal"),
				msg:       "ARC-Seal is found",
				domainKey: domainKey,
			}
		}
		s += canonical.Header(header, canonical.Canonicalization(ams.canonnAndAlgo.Header))
	}
	// 末尾の\r\nを削除し、再度追加して、末尾に正確に一つの\r\nがあることを保証する
	s = strings.TrimSuffix(s, "\r\n")
	s += "\r\n"

	// 署名をbase64デコード
	signature, err := base64Decode(ams.Signature)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode arc-message-signature signature: %v", err),
			msg:       "invalid signature",
			domainKey: domainKey,
		}
	}

	// 署名するヘッダをハッシュ化
	hash := ams.canonnAndAlgo.HashAlgo.New()
	hash.Write([]byte(s))

	// 署名の検証
	decoded, err := base64Decode(domainKey.PublicKey)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode domainkey public key: %v", err),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	// 公開鍵をパース
	// RFC 8463: ed25519 public key is raw 32-octet key, not PKIX
	pub, err := domainkey.ParseDKIMPublicKey(decoded, domainKey.KeyType)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to parse domainkey public key: %v", err),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// 署名の検証
		if err := rsa.VerifyPKCS1v15(pub, ams.canonnAndAlgo.HashAlgo, hash.Sum(nil), signature); err != nil {
			return &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify arc-message-signature signature: %v", err),
				msg:       "invalid signature",
				domainKey: domainKey,
			}
		}
	case ed25519.PublicKey:
		// 署名の検証
		if !ed25519.Verify(pub, hash.Sum(nil), signature) {
			return &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify arc-message-signature signature"),
				msg:       "invalid signature",
				domainKey: domainKey,
			}
		}
	default:
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to convert arc-message-signature public key to rsa or ed25519"),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	return &VerifyResult{
		status:    VerifyStatusPass,
		err:       nil,
		msg:       "good signature",
		domainKey: domainKey,
	}
}
