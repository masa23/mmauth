package arc

import (
	"errors"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestARCInvalidDNSKeyTypes(t *testing.T) {
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	headers := []string{"From: a@example.com\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: bh}
	if e := ams.Sign(headers, testKeys.RSAPrivateKey); e != nil {
		t.Fatal(e)
	}
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultNone}
	if e := seal.Sign(headers, testKeys.RSAPrivateKey); e != nil {
		t.Fatal(e)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")
	old := domainkey.DefaultResolver
	defer func() { domainkey.DefaultResolver = old }()
	for _, tag := range []string{"", "k=rsa; ", "k=unsupported; ", "k=; ", "k=rsa:unsupported; "} {
		t.Run(tag, func(t *testing.T) {
			domainkey.DefaultResolver = func(string) ([]string, error) {
				return []string{"v=DKIM1; " + tag + "p=" + testKeys.RSAPublicKeyBase64}, nil
			}
			sigs, e := ParseARCHeaders(headers)
			if e != nil {
				t.Fatal(e)
			}
			sig := sigs.GetInstance(1)
			sig.Verify(headers, bh, nil)
			want := VerifyStatusPass
			chain := VerifyStatusPass
			if tag != "" && tag != "k=rsa; " {
				want = VerifyStatusPermErr
				chain = VerifyStatusFail
			}
			for _, result := range []*VerifyResult{sig.messageResult, sig.sealResult} {
				if result.Status() != want {
					t.Fatalf("status=%s want=%s error=%v", result.Status(), want, result.Error())
				}
				if want == VerifyStatusPermErr && !errors.Is(result.Error(), domainkey.ErrInvalidKeyType) {
					t.Fatal(result.Error())
				}
			}
			if sigs.GetVerifyResult() != chain {
				t.Fatal(sigs.GetVerifyResultString())
			}
		})
	}
}
