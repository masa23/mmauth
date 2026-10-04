package arc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestARCKeyVersions(t *testing.T) {
	sealKey, sealDK := regressionARCKey(t)
	messageKey, messageDK := regressionARCKey(t)
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	headers := []string{"From: a@example.com\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "message", Canonicalization: "relaxed/relaxed", BodyHash: bh}
	if err := ams.Sign(headers, messageKey); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "seal", ChainValidation: ChainValidationResultNone}
	if err := seal.Sign(headers, sealKey); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")

	old := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = old }()
	for _, tc := range []struct{ name, sealVersion, messageVersion string }{
		{"valid", "DKIM1", "DKIM1"},
		{"omitted", "", ""},
		{"mixed defaults", "DKIM1", ""},
		{"invalid seal", "DKIM2", "DKIM1"},
		{"invalid message", "DKIM1", "DKIM2"},
		{"invalid case", "dkim1", "DKIM1.0"},
	} {
		for _, fromDNS := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/DNS=%t", tc.name, fromDNS), func(t *testing.T) {
				record := func(version, publicKey string) string {
					prefix := ""
					if version != "" {
						prefix = "v=" + version + "; "
					}
					return prefix + "k=ed25519; p=" + publicKey
				}
				sealRecord := record(tc.sealVersion, sealDK.PublicKey)
				messageRecord := record(tc.messageVersion, messageDK.PublicKey)
				queries := map[string]int{}
				domainkey.DefaultResolver = func(name string) ([]string, error) {
					queries[name]++
					switch name {
					case "seal._domainkey.example.com":
						return []string{sealRecord}, nil
					case "message._domainkey.example.com":
						return []string{messageRecord}, nil
					}
					return nil, fmt.Errorf("unexpected query: %s", name)
				}
				sigs, err := ParseARCHeaders(headers)
				if err != nil {
					t.Fatal(err)
				}
				sig := sigs.GetInstance(1)
				if fromDNS {
					sig.Verify(headers, bh, nil)
					if queries["seal._domainkey.example.com"] != 1 || queries["message._domainkey.example.com"] != 1 {
						t.Fatalf("keys must be fetched independently: %v", queries)
					}
				} else {
					sk, err := domainkey.ParseDomainKeyRecord(sealRecord)
					if err != nil {
						t.Fatal(err)
					}
					mk, err := domainkey.ParseDomainKeyRecord(messageRecord)
					if err != nil {
						t.Fatal(err)
					}
					sig.VerifyWithKeys(headers, bh, &sk, &mk)
					if len(queries) != 0 {
						t.Fatalf("explicit keys caused DNS lookup: %v", queries)
					}
				}
				wantChain := VerifyStatusPass
				for _, check := range []struct {
					version string
					result  *VerifyResult
				}{{tc.sealVersion, sig.sealResult}, {tc.messageVersion, sig.messageResult}} {
					want := VerifyStatusPass
					if check.version != "" && check.version != "DKIM1" {
						want, wantChain = VerifyStatusPermErr, VerifyStatusFail
						if !errors.Is(check.result.Error(), domainkey.ErrInvalidVersion) {
							t.Fatalf("invalid version error lost: %v", check.result.Error())
						}
					}
					if check.result.Status() != want {
						t.Fatalf("version=%q status=%s want=%s", check.version, check.result.Status(), want)
					}
				}
				if got := sigs.GetVerifyResult(); got != wantChain {
					t.Fatalf("chain=%s want=%s", got, wantChain)
				}
			})
		}
	}
}
