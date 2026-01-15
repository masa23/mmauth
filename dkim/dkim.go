package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/dkimheader"
	"github.com/masa23/mmauth/internal/header"
)

// 正規化
type Canonicalization canonical.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// DKIMの署名アルゴリズム
type SignatureAlgorithm string

const (
	// rsa-sha1はセキュリティ上の理由から使用を推奨しません
	SignatureAlgorithmRSA_SHA1   SignatureAlgorithm = "rsa-sha1"
	SignatureAlgorithmRSA_SHA256 SignatureAlgorithm = "rsa-sha256"
	// ed25519-sha256は実験的な機能です
	SignatureAlgorithmED25519_SHA256 SignatureAlgorithm = "ed25519-sha256"
)

type CanonicalizationAndAlgorithm struct {
	Header    Canonicalization
	Body      Canonicalization
	Algorithm SignatureAlgorithm
	Limit     int64
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

type Signature struct {
	Algorithm           SignatureAlgorithm // a algorithm
	Signature           string             // b signature
	BodyHash            string             // bh body hash
	Canonicalization    string             // c canonicalization
	Domain              string             // d domain
	Headers             string             // h headers
	Identity            string             // i identity
	Limit               int64              // l limit length
	QueryType           string             // q query
	Selector            string             // s selector
	Timestamp           int64              // t timestamp
	Version             int                // v version
	SignatureExpiration int64              // x signature expiration
	VerifyResult        *VerifyResult
	raw                 string
	canonnAndAlgo       *CanonicalizationAndAlgorithm
}

func (ds *Signature) GetCanonicalizationAndAlgorithm() *CanonicalizationAndAlgorithm {
	return ds.canonnAndAlgo
}

func (ds *Signature) String() string {
	return fmt.Sprintf("a=%s; bh=%s;\r\n"+
		"        c=%s; d=%s;\r\n"+
		"        h=%s;\r\n"+
		"        s=%s; t=%d; v=%d;\r\n"+
		"        b=%s",
		ds.Algorithm, ds.BodyHash,
		ds.Canonicalization, ds.Domain,
		ds.Headers,
		ds.Selector, ds.Timestamp, ds.Version,
		header.WrapSignatureWithBreaks(ds.Signature),
	)
}

func (ds *Signature) ResultString() string {
	if ds.VerifyResult == nil || ds.VerifyResult.status == VerifyStatusNeutral || ds.VerifyResult.status == VerifyStatusNone {
		return "dkim=none"
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("dkim=%s (%s)", ds.VerifyResult.Status(), ds.VerifyResult.Message()))

	if ds.Domain != "" {
		result.WriteString(fmt.Sprintf(" header.d=%s", ds.Domain))
	}
	if ds.Selector != "" {
		result.WriteString(fmt.Sprintf(" header.s=%s", ds.Selector))
	}
	if ds.Identity != "" {
		result.WriteString(fmt.Sprintf(" header.i=%s", ds.Identity))
	}
	return result.String()
}

// stripFWS はFWS (Folding White Space) を削除する
// FWS = WSP*(CRLF WSP+)
func stripFWS(s string) string {
	// まず、CRLFとそれに続く空白文字を削除
	s = strings.ReplaceAll(s, "\r\n", "")
	// 次に、タブとスペースを削除
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// DKIM-SignatureヘッダをパースしDKIMSignatureを返す
func ParseSignature(s string) (*Signature, error) {
	result := &Signature{}
	result.raw = s

	// ヘッダと値に分割
	k, v := header.ParseHeaderField(s)
	if !strings.EqualFold(k, "dkim-signature") {
		return nil, fmt.Errorf("invalid header field")
	}
	params, err := dkimheader.ParseSignatureParams(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DKIM-Signature header field: %v", err)
	}

	seenTags := make(map[string]bool)
	for key, value := range params {
		if seenTags[key] {
			return nil, fmt.Errorf("duplicate tag '%s' found in DKIM-Signature", key)
		}
		seenTags[key] = true
		value = header.StripWhiteSpace(value)
		switch key {
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
			result.Signature = stripFWS(value)
		case "bh":
			result.BodyHash = stripFWS(value)
		case "c":
			result.Canonicalization = value
		case "d":
			result.Domain = value
		case "h":
			result.Headers = value
		case "i":
			result.Identity = value
		case "l":
			limit, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid limit for 'l' field: %s", value)
			}
			if limit < 0 {
				return nil, fmt.Errorf("invalid limit for 'l' field: %s", value)
			}
			result.Limit = limit
		case "q":
			result.QueryType = value
		case "s":
			result.Selector = value
		case "t":
			timestamp, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp")
			}
			result.Timestamp = timestamp
		case "v":
			version, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid version")
			}
			result.Version = version
		case "x":
			expiration, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid signature expiration")
			}
			result.SignatureExpiration = expiration
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
		Limit:     result.Limit,
		HashAlgo:  hashAlgo(result.Algorithm),
	}

	// h=タグが空でないことを検証
	if result.Headers == "" {
		return nil, fmt.Errorf("h= tag must not be empty")
	}

	// h=タグにFromヘッダが含まれていることを検証 (RFC 6376要求事項)
	headersList := strings.Split(result.Headers, ":")
	fromIncluded := false
	for _, h := range headersList {
		if strings.ToLower(strings.TrimSpace(h)) == "from" {
			fromIncluded = true
			break
		}
	}
	if !fromIncluded {
		return nil, fmt.Errorf("h= tag must include 'From' header")
	}

	// i=タグの補完とドメイン整合性の検証 (RFC 6376要件)
	if result.Identity == "" {
		// i=タグが存在しない場合、デフォルト値として "@" + d を設定
		result.Identity = "@" + result.Domain
	} else {
		// Identityからドメイン部分を抽出
		atIndex := strings.LastIndex(result.Identity, "@")
		if atIndex != -1 {
			identityDomain := result.Identity[atIndex+1:]
			// d=タグのドメインがi=タグのドメインと同じかサブドメインであることを確認
			if result.Domain != identityDomain && !strings.HasSuffix(identityDomain, "."+result.Domain) {
				return nil, fmt.Errorf("i= tag domain must be the same as or a subdomain of d= tag domain")
			}
		}
	}

	// x=タグの値がt=タグの値より大きいことの検証 (RFC 6376要件)
	// 署名の有効期限は署名時刻より後でなければならない
	if result.SignatureExpiration != 0 && result.Timestamp != 0 {
		if result.SignatureExpiration <= result.Timestamp {
			return nil, fmt.Errorf("x= tag value must be greater than t= tag value")
		}
	}

	return result, nil
}

// DKIMSignatureに署名を行う
func (d *Signature) Sign(headers []string, key crypto.Signer) error {
	// DKIM Version Check
	if d.Version != 1 {
		return errors.New("dkim: invalid version")
	}
	// headersのヘッダ名を抽出する
	var h []string
	for _, header := range headers {
		k, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		h = append(h, k)
	}
	canHeader, _, err := header.ParseHeaderCanonicalization(d.Canonicalization)
	if err != nil {
		return err
	}
	d.Headers = strings.Join(h, ":")
	// timestampを設定
	if d.Timestamp == 0 {
		d.Timestamp = time.Now().Unix()
	}

	// 署名アルゴリズムが指定されていない場合は鍵のタイプから自動設定
	if d.Algorithm == "" {
		switch key.Public().(type) {
		case *rsa.PublicKey:
			d.Algorithm = SignatureAlgorithmRSA_SHA256
		case ed25519.PublicKey:
			d.Algorithm = SignatureAlgorithmED25519_SHA256
		default:
			return fmt.Errorf("unknown key type: %T", key.Public())
		}
	}

	// 署名対象のヘッダを正規化
	var normalizedHeaders []string
	for _, h := range headers {
		normalizedHeaders = append(normalizedHeaders, canonical.Header(h, canonical.Canonicalization(canHeader)))
	}

	// DKIM-Signatureヘッダのb=タグの値を空文字列として扱う
	dkimSigHeader := "DKIM-Signature: " + d.String()
	// b=タグの値を空文字列に置き換える
	dkimSigHeader = strings.Replace(dkimSigHeader, "b="+d.Signature, "b=", 1)
	normalizedHeaders = append(normalizedHeaders, dkimSigHeader)

	// 適切なハッシュアルゴリズムを選択
	hashAlgo := hashAlgo(d.Algorithm)
	signature, err := header.Signer(normalizedHeaders, key, canHeader, hashAlgo)
	if err != nil {
		return err
	}
	d.Signature = signature
	return nil
}

// DKIMSignatureを検証する
// domainKeyがnilの場合はLookupDomainKeyを実行
func (d *Signature) Verify(headers []string, bodyHash string, domainKey *domainkey.DomainKey) {
	d.VerifyWithResolver(headers, bodyHash, domainKey, nil)
}

// DKIMSignatureを検証する
// domainKeyがnilの場合はLookupDomainKeyを実行
// resolverがnilの場合はデフォルトのリゾルバーを使用
func (d *Signature) VerifyWithResolver(headers []string, bodyHash string, domainKey *domainkey.DomainKey, resolver domainkey.TXTResolver) {
	// domainKeyがnilの場合はLookupDomainKeyを実行
	if domainKey == nil {
		// リゾルバーがnilの場合はタイムアウト付きのデフォルトリゾルバーを作成
		if resolver == nil {
			resolver = domainkey.NewDefaultTXTResolver()
		}

		domKey, err := domainkey.LookupDKIMDomainKeyWithResolver(d.Selector, d.Domain, resolver)
		if errors.Is(err, domainkey.ErrNoRecordFound) {
			d.VerifyResult = &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("domain key is not found: %v", err),
				msg:    "domain key is not found",
			}
			return
		} else if err != nil {
			d.VerifyResult = &VerifyResult{
				status: VerifyStatusTempErr,
				err:    fmt.Errorf("failed to lookup domain key: %v", err),
				msg:    "failed to lookup domain key",
			}
			return
		}
		domainKey = &domKey
	}

	// テストモードの確認
	testFlagMsg := ""
	if domainKey.IsTestFlag() {
		testFlagMsg = " test mode"
	}

	// service typeの確認 (RFC 6376要件)
	if !domainKey.IsService(domainkey.ServiceTypeEmail) {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("domain key service type is invalid: %v", domainKey.ServiceType),
			msg:       "service type is invalid" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// DKIM-Signatureがない場合はneutral (RFC 6376要件)
	if d.raw == "" {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusNeutral,
			err:       errors.New("DKIM-Signature is not found"),
			msg:       "signature is not found" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// バージョンを検証 (RFC 6376要件)
	if d.Version != 1 {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("DKIM-Signature version is invalid: %d", d.Version),
			msg:       "version is invalid" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// expireを検証 (RFC 6376要件)
	// TimestampとSignatureExpirationがセットされてない場合は検証しない
	if d.SignatureExpiration != 0 {
		// 現在時刻がSignatureExpirationを超えていたらFail
		now := time.Now().Unix()
		if now > d.SignatureExpiration {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("DKIM-Signature is expired: now=%d expiration=%d", now, d.SignatureExpiration),
				msg:       "signature is expired" + testFlagMsg,
				domainKey: domainKey,
			}
			return
		}

		// TimestampがSignatureExpirationより大きい場合はエラー (RFC 6376違反)
		if d.Timestamp > d.SignatureExpiration {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusPermErr,
				err:       fmt.Errorf("DKIM-Signature timestamp is greater than expiration: timestamp=%d expiration=%d", d.Timestamp, d.SignatureExpiration),
				msg:       "signature timestamp is greater than expiration" + testFlagMsg,
				domainKey: domainKey,
			}
			return
		}
	}

	// ボディーハッシュを検証 (RFC 6376要件)
	if d.BodyHash != bodyHash {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusFail,
			err:       fmt.Errorf("DKIM-Signature body hash is not match: %s != %s", d.BodyHash, bodyHash),
			msg:       "body hash is not match" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// ヘッダの抽出と連結
	h := header.ExtractHeadersDKIM(headers, strings.Split(d.Headers, ":"))
	dkimSigHeader := dkimheader.StripBValueForSigning(d.raw)

	// ヘッダの正規化
	var s string
	for _, header := range h {
		s += canonical.Header(header, canonical.Canonicalization(d.canonnAndAlgo.Header))
	}
	// DKIM-Signatureヘッダの正規化
	s += canonical.Header(dkimSigHeader, canonical.Canonicalization(d.canonnAndAlgo.Header))
	// 末尾のCRLFを削除 (DKIM-Signatureヘッダの分は既に削除されている)
	s = strings.TrimSuffix(s, "\r\n")

	// 署名をbase64デコード
	signature, err := base64Decode(d.Signature)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusFail,
			err:       fmt.Errorf("failed to decode signature: %v", err),
			msg:       "invalid signature" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// 署名するヘッダをハッシュ化
	hash := d.canonnAndAlgo.HashAlgo.New()
	hash.Write([]byte(s))

	// 署名を検証
	// public keyをbase64デコード
	decoded, err := base64Decode(domainKey.PublicKey)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode public key: %v", err),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// 公開鍵をパース
	// RFC 8463: ed25519 public key is raw 32-octet key, not PKIX
	pub, err := domainkey.ParseDKIMPublicKey(decoded, domainKey.KeyType)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to parse public key: %v", err),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	// RSAかed25519の公開鍵か確認
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// 署名を検証
		if err := rsa.VerifyPKCS1v15(pub, d.canonnAndAlgo.HashAlgo, hash.Sum(nil), signature); err != nil {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify signature: %v", err),
				msg:       "invalid signature" + testFlagMsg,
				domainKey: domainKey,
			}
			return
		}
	case ed25519.PublicKey:
		// 署名を検証
		if !ed25519.Verify(pub, hash.Sum(nil), signature) {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify signature: %v", err),
				msg:       "invalid signature" + testFlagMsg,
				domainKey: domainKey,
			}
			return
		}
	default:
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("invalid public key type: %T", pub),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
		return
	}

	d.VerifyResult = &VerifyResult{
		status:    VerifyStatusPass,
		err:       nil,
		msg:       "good signature" + testFlagMsg,
		domainKey: domainKey,
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
