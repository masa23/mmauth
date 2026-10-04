package arc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestARCKeyRestrictions(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	old := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = old }()
	for _, tc := range []struct {
		restriction string
		want        VerifyStatus
	}{
		{"", VerifyStatusPass}, {"h=sha256; s=email", VerifyStatusPass},
		{"s=*", VerifyStatusPass}, {"h=sha512:sha256; s=other:email", VerifyStatusPass},
		{"h=sha1", VerifyStatusPermErr}, {"h=sha512", VerifyStatusPermErr},
		{"s=other", VerifyStatusPermErr}, {"h=", VerifyStatusPermErr}, {"s=", VerifyStatusPermErr},
	} {
		for _, target := range []string{"AS", "AMS"} {
			for _, source := range []string{"explicit", "cache", "DNS"} {
				t.Run(fmt.Sprintf("%s/%s/%s", target, source, tc.restriction), func(t *testing.T) {
					record := "v=DKIM1; k=ed25519; p=" + dk.PublicKey + "; " + tc.restriction
					restricted, err := domainkey.ParseDomainKeyRecord(record)
					if err != nil {
						t.Fatal(err)
					}
					if source == "cache" {
						data, err := json.Marshal(restricted)
						if err != nil {
							t.Fatal(err)
						}
						restricted = domainkey.DomainKey{}
						if err := json.Unmarshal(data, &restricted); err != nil {
							t.Fatal(err)
						}
					}
					calls := 0
					domainkey.DefaultResolver = func(name string) ([]string, error) {
						calls++
						if name != "s._domainkey.example.com" {
							return nil, fmt.Errorf("unexpected query: %s", name)
						}
						return []string{record}, nil
					}
					candidate := &restricted
					if source == "DNS" {
						candidate = nil
					}
					sigs, err := ParseARCHeaders(headers)
					if err != nil {
						t.Fatal(err)
					}
					sig := sigs.GetInstance(1)
					var result, other *VerifyResult
					if target == "AS" {
						sig.VerifyWithKeys(headers, bh, candidate, dk)
						result, other = sig.sealResult, sig.messageResult
					} else {
						sig.VerifyWithKeys(headers, bh, dk, candidate)
						result, other = sig.messageResult, sig.sealResult
					}
					if result.Status() != tc.want || other.Status() != VerifyStatusPass {
						t.Fatalf("target=%s want=%s other=%s error=%v", result.Status(), tc.want, other.Status(), result.Error())
					}
					wantChain := VerifyStatusPass
					if tc.want != VerifyStatusPass {
						wantChain = VerifyStatusFail
					}
					if sigs.GetVerifyResult() != wantChain {
						t.Fatalf("chain=%s want=%s", sigs.GetVerifyResult(), wantChain)
					}
					wantCalls := 0
					if source == "DNS" {
						wantCalls = 1
					}
					if calls != wantCalls {
						t.Fatalf("DNS calls=%d want=%d", calls, wantCalls)
					}
				})
			}
		}
	}
}

func TestARCKeyTypes(t *testing.T) {
	edKey, edDK := regressionARCKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublicKey, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	rsaDK := &domainkey.DomainKey{KeyType: domainkey.KeyTypeRSA, PublicKey: base64.StdEncoding.EncodeToString(rsaPublicKey)}
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	old := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = old }()
	for _, tc := range []struct {
		name      string
		algorithm SignatureAlgorithm
		key       crypto.Signer
		domainKey *domainkey.DomainKey
		keyType   domainkey.KeyType
		want      VerifyStatus
	}{
		{"rsa-sha1", SignatureAlgorithmRSA_SHA1, rsaKey, rsaDK, domainkey.KeyTypeRSA, VerifyStatusPass},
		{"rsa-sha256", SignatureAlgorithmRSA_SHA256, rsaKey, rsaDK, domainkey.KeyTypeRSA, VerifyStatusPass},
		{"rsa-default", SignatureAlgorithmRSA_SHA256, rsaKey, rsaDK, "", VerifyStatusPass},
		{"ed25519", SignatureAlgorithmED25519_SHA256, edKey, edDK, domainkey.KeyTypeED25519, VerifyStatusPass},
		{"rsa-sha1-with-ed25519", SignatureAlgorithmRSA_SHA1, edKey, edDK, domainkey.KeyTypeED25519, VerifyStatusPermErr},
		{"rsa-sha256-with-ed25519", SignatureAlgorithmRSA_SHA256, edKey, edDK, domainkey.KeyTypeED25519, VerifyStatusPermErr},
		{"ed25519-with-rsa", SignatureAlgorithmED25519_SHA256, rsaKey, rsaDK, domainkey.KeyTypeRSA, VerifyStatusPermErr},
		{"ed25519-with-default-rsa", SignatureAlgorithmED25519_SHA256, rsaKey, rsaDK, "", VerifyStatusPermErr},
	} {
		for _, target := range []string{"AS", "AMS"} {
			for _, source := range []string{"explicit", "DNS"} {
				t.Run(fmt.Sprintf("%s/%s/%s", tc.name, target, source), func(t *testing.T) {
					headers := []string{"From: a@example.com\r\n"}
					ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: bh}
					if target == "AMS" {
						ams.Algorithm = tc.algorithm
					}
					// Sign with the actual key even when a= declares another algorithm,
					// so a cryptographic failure cannot hide the missing policy check.
					if err := ams.Sign(headers, tc.key); err != nil {
						t.Fatal(err)
					}
					headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
					seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultNone}
					if target == "AS" {
						seal.Algorithm = tc.algorithm
					}
					if err := seal.Sign(headers, tc.key); err != nil {
						t.Fatal(err)
					}
					headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")
					candidate := *tc.domainKey
					candidate.KeyType = tc.keyType
					domainkey.DefaultResolver = func(name string) ([]string, error) {
						if name != "s._domainkey.example.com" {
							return nil, fmt.Errorf("unexpected query: %s", name)
						}
						record := "v=DKIM1; p=" + candidate.PublicKey
						if candidate.KeyType != "" {
							record += "; k=" + string(candidate.KeyType)
						}
						return []string{record}, nil
					}
					key := &candidate
					if source == "DNS" {
						key = nil
					}
					sigs, err := ParseARCHeaders(headers)
					if err != nil {
						t.Fatal(err)
					}
					sig := sigs.GetInstance(1)
					var result, other *VerifyResult
					if target == "AS" {
						sig.VerifyWithKeys(headers, bh, key, tc.domainKey)
						result, other = sig.sealResult, sig.messageResult
					} else {
						sig.VerifyWithKeys(headers, bh, tc.domainKey, key)
						result, other = sig.messageResult, sig.sealResult
					}
					if result.Status() != tc.want || other.Status() != VerifyStatusPass {
						t.Fatalf("target=%s want=%s other=%s error=%v", result.Status(), tc.want, other.Status(), result.Error())
					}
					wantChain := VerifyStatusPass
					if tc.want != VerifyStatusPass {
						wantChain = VerifyStatusFail
						if result.Error() == nil || result.Error().Error() != "signature key type is not allowed by domain key" {
							t.Fatalf("key type policy error=%v", result.Error())
						}
					}
					if sigs.GetVerifyResult() != wantChain {
						t.Fatalf("chain=%s want=%s", sigs.GetVerifyResult(), wantChain)
					}
				})
			}
		}
	}
}
