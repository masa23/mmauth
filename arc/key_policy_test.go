package arc

import (
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
