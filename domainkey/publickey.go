package domainkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// ParseDKIMPublicKey parses the decoded value of the "p=" tag according to the
// DKIM/ARC key type (k=).
//
// RFC 6376 defines k=rsa public keys as ASN.1 DER encoded RSAPublicKey
// (PKCS#1), base64-encoded in DNS.
// RFC 8463 defines k=ed25519 public keys as a 32‑octet raw public key,
// base64-encoded in DNS.
//
// For interoperability, this function also accepts SubjectPublicKeyInfo (PKIX)
// form for RSA as a fallback.
func ParseDKIMPublicKey(decoded []byte, keyType KeyType) (crypto.PublicKey, error) {
	if keyType == "" {
		keyType = KeyTypeRSA
	}

	switch keyType {
	case KeyTypeRSA:
		// RFC 6376: RSAPublicKey (PKCS#1) DER
		if pub, err := x509.ParsePKCS1PublicKey(decoded); err == nil {
			return pub, nil
		}
		// Interoperability: accept PKIX (SPKI) if present.
		pub, err := x509.ParsePKIXPublicKey(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rsa public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid rsa public key type: %T", pub)
		}
		return rsaPub, nil

	case KeyTypeED25519:
		// RFC 8463 §4.2 encodes the 256-bit public key directly in p=.
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(decoded))
		}
		return ed25519.PublicKey(decoded), nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}
