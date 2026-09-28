package domainkey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type TXTLookupFunc func(name string) ([]string, error)

// TXTResolver is an interface for DNS TXT record lookups.
type TXTResolver interface {
	// LookupTXT performs a DNS TXT record lookup for the given name.
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// defaultTXTResolver is the default implementation of TXTResolver using net.Resolver.
type defaultTXTResolver struct {
	resolver *net.Resolver
}

// NewDefaultTXTResolver creates a new default TXTResolver.
func NewDefaultTXTResolver() TXTResolver {
	return &defaultTXTResolver{
		resolver: net.DefaultResolver,
	}
}

// LookupTXT performs a DNS TXT record lookup using the default system resolver.
func (r *defaultTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}

// DefaultResolver is the default TXT lookup function.
var DefaultResolver TXTLookupFunc = func(name string) ([]string, error) {
	// 5秒のタイムアウトを設定
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := NewDefaultTXTResolver()
	return resolver.LookupTXT(ctx, name)
}

var (
	ErrNoRecordFound        = errors.New("no record found")
	ErrDNSLookupFailed      = errors.New("dns lookup failed")
	ErrInvalidHashAlgo      = errors.New("invalid hash algorithm")
	ErrInvalidKeyType       = errors.New("invalid key type")
	ErrInvalidServiceType   = errors.New("invalid service type")
	ErrInvalidSelectorFlags = errors.New("invalid selector flags")
	ErrInvalidVersion       = errors.New("invalid version")
)

// dnsLookupError preserves the resolver error and supports errors.Is with the
// package sentinel, including on Go 1.19 (which predates multiple %w values).
type dnsLookupError struct{ cause error }

func (e *dnsLookupError) Error() string        { return ErrDNSLookupFailed.Error() + ": " + e.cause.Error() }
func (e *dnsLookupError) Unwrap() error        { return e.cause }
func (e *dnsLookupError) Is(target error) bool { return target == ErrDNSLookupFailed }

type HashAlgo string

const (
	HashAlgoSHA1   HashAlgo = "sha1"
	HashAlgoSHA256 HashAlgo = "sha256"
)

type KeyType string

const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeED25519 KeyType = "ed25519"
)

type ServiceType string

const (
	ServiceTypeEmail ServiceType = "email"
	ServiceTypeAll   ServiceType = "*"
)

type SelectorFlags string

const (
	SelectorFlagsTest         SelectorFlags = "y"
	SelectorFlagsStrictDomain SelectorFlags = "s" // identifier is strict domain
)

type DomainKey struct {
	HashAlgo      []HashAlgo      // h hash algorithm separated by colons
	KeyType       KeyType         // k default:rsa
	Notes         string          // n notes
	PublicKey     string          // p public key base64 encoded
	ServiceType   []ServiceType   // s service type separated by colons
	SelectorFlags []SelectorFlags // t flags separated by colons
	Version       string          // v version default:DKIM1
	raw           string          // raw record
	// These flags preserve explicit h=/s= restrictions even if every listed
	// value is unknown. They must survive serialization of cached keys.
	HashRestricted    bool `json:",omitempty"`
	ServiceRestricted bool `json:",omitempty"`
}

// テストフラグが立っているか
func (d *DomainKey) IsTestFlag() bool {
	for _, f := range d.SelectorFlags {
		if f == SelectorFlagsTest {
			return true
		}
	}
	return false
}

// サービスタイプが指定されたものか
func (d *DomainKey) IsService(service ServiceType) bool {
	if service == ServiceTypeAll {
		return true
	}
	// service typeが指定されていない場合は全てのサービスに対応
	if len(d.ServiceType) == 0 && !d.ServiceRestricted {
		return true
	}
	for _, s := range d.ServiceType {
		if s == service || s == ServiceTypeAll {
			return true
		}
	}
	return false
}

// isKeyRevoked checks if a domain key has been revoked.
// A key is considered revoked if the record contains "p=" but the parsed PublicKey is empty.
func isKeyRevoked(record string, domainKey DomainKey) error {
	if strings.Contains(record, "p=") && domainKey.PublicKey == "" {
		return fmt.Errorf("key revoked: %w", ErrNoRecordFound)
	}
	return nil
}

// LookupDKIMDomainKey DKIMのドメインキーをLookupする
// versionがDKIM1でない場合はエラーを返す
func LookupDKIMDomainKey(selector, domain string) (DomainKey, error) {
	d, err := lookupDomainKey(selector, domain)
	if err != nil {
		return DomainKey{}, err
	}
	if d.Version != "" && d.Version != "DKIM1" {
		return DomainKey{}, ErrInvalidVersion
	}
	return d, nil
}

// LookupDKIMDomainKeyWithResolver DKIMのドメインキーをLookupする
// versionがDKIM1でない場合はエラーを返す
// resolverがnilの場合はデフォルトのリゾルバーを使用
func LookupDKIMDomainKeyWithResolver(selector, domain string, resolver TXTResolver) (DomainKey, error) {
	d, err := lookupDomainKeyWithResolver(selector, domain, resolver)
	if err != nil {
		return DomainKey{}, err
	}
	if d.Version != "" && d.Version != "DKIM1" {
		return DomainKey{}, ErrInvalidVersion
	}
	return d, nil
}

// LookupARCDomainKey ARCのドメインキーを検索する
// DKIMと同じ鍵バージョンを要求する。versionの省略は許可する。
func LookupARCDomainKey(selector, domain string) (DomainKey, error) {
	return LookupDKIMDomainKey(selector, domain)
}

// lookupDomainKey
func lookupDomainKey(selector, domain string) (DomainKey, error) {
	query := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	res, err := DefaultResolver(query)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return DomainKey{}, ErrNoRecordFound
		}
		return DomainKey{}, &dnsLookupError{cause: err}
	}
	return parseDomainKeyRecords(res)
}

// parseDomainKeyRecords parses DNS TXT records and extracts the domain key.
// Returns the first valid domain key with a non-empty public key.
func parseDomainKeyRecords(records []string) (DomainKey, error) {
	for _, r := range records {
		domainKey, err := ParseDomainKeyRecord(r)
		if err != nil {
			return DomainKey{}, err
		}
		if domainKey.PublicKey != "" {
			return domainKey, nil
		}
		// p=が空の場合はキーが撤回されたとみなす
		if err := isKeyRevoked(r, domainKey); err != nil {
			return DomainKey{}, err
		}
	}
	return DomainKey{}, ErrNoRecordFound
}

// lookupDomainKeyWithResolver
func lookupDomainKeyWithResolver(selector, domain string, resolver TXTResolver) (DomainKey, error) {
	query := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	var res []string
	var err error

	// If resolver is nil, use the default resolver
	if resolver == nil {
		res, err = DefaultResolver(query)
	} else {
		// Use the provided resolver
		// 5秒のタイムアウトを設定
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err = resolver.LookupTXT(ctx, query)
	}

	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return DomainKey{}, ErrNoRecordFound
		}
		return DomainKey{}, &dnsLookupError{cause: err}
	}

	return parseDomainKeyRecords(res)
}

// ドメインキーレコードの解析
func ParseDomainKeyRecord(r string) (DomainKey, error) {
	var key DomainKey
	key.raw = r

	pairs := strings.Split(r, ";")
	for _, pair := range pairs {
		k, v, _ := strings.Cut(pair, "=")
		// 値の前後の空白をトリム
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "v":
			key.Version = v
			continue
		case "h":
			key.HashRestricted = true
			algos := strings.Split(v, ":")
			for _, algo := range algos {
				trimmedAlgo := strings.TrimSpace(algo)
				switch HashAlgo(trimmedAlgo) {
				case HashAlgoSHA1:
					key.HashAlgo = append(key.HashAlgo, HashAlgoSHA1)
				case HashAlgoSHA256:
					key.HashAlgo = append(key.HashAlgo, HashAlgoSHA256)
				// RFC 6376: Unrecognized algorithms MUST be ignored
				default:
					// Unknown algorithms are ignored per RFC 6376 Section 3.6.1
				}
			}
		case "k":
			keyTypes := strings.Split(v, ":")
			for _, keyType := range keyTypes {
				trimmedKeyType := strings.TrimSpace(keyType)
				switch KeyType(trimmedKeyType) {
				case KeyTypeRSA:
					key.KeyType = KeyTypeRSA
				case KeyTypeED25519:
					key.KeyType = KeyTypeED25519
				// RFC 6376: Unrecognized key types MUST be ignored
				default:
					// Unknown key types are ignored per RFC 6376 Section 3.6.1
				}
			}
		case "n":
			key.Notes = v
		case "p":
			// 空白を削除して格納
			key.PublicKey = strings.ReplaceAll(v, " ", "")
		case "s":
			key.ServiceRestricted = true
			serviceTypes := strings.Split(v, ":")
			for _, serviceType := range serviceTypes {
				trimmedServiceType := strings.TrimSpace(serviceType)
				switch ServiceType(trimmedServiceType) {
				case ServiceTypeEmail:
					key.ServiceType = append(key.ServiceType, ServiceTypeEmail)
				case ServiceTypeAll:
					key.ServiceType = append(key.ServiceType, ServiceTypeAll)
				// RFC 6376: Unrecognized service types MUST be ignored
				default:
					// Unknown service types are ignored per RFC 6376 Section 3.6.1
				}
			}
		case "t":
			// t=タグはコロン区切りの複数フラグを許容する
			flags := strings.Split(v, ":")
			for _, flag := range flags {
				trimmedFlag := strings.TrimSpace(flag)
				switch SelectorFlags(trimmedFlag) {
				case SelectorFlagsTest:
					key.SelectorFlags = append(key.SelectorFlags, SelectorFlagsTest)
				case SelectorFlagsStrictDomain:
					key.SelectorFlags = append(key.SelectorFlags, SelectorFlagsStrictDomain)
				// 未知のフラグは無視する（将来拡張に対応）
				default:
					// 未知のフラグはエラーにせず、単に無視する
					// return DomainKey{}, ErrInvalidSelectorFlags
				}
			}
		}
	}

	return key, nil
}

// AllowsHash reports whether an algorithm is permitted by h=. An explicitly
// specified list containing only unknown algorithms permits no known algorithm.
func (d *DomainKey) AllowsHash(algo HashAlgo) bool {
	if !d.HashRestricted && len(d.HashAlgo) == 0 {
		return true
	}
	for _, allowed := range d.HashAlgo {
		if allowed == algo {
			return true
		}
	}
	return false
}
