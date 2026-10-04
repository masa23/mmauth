package dkim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

type keyVersionResolver struct{ record string }

func (r keyVersionResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{r.record}, nil
}

func TestDKIMKeyVersions(t *testing.T) {
	key, dk := regressionKey(t)
	headers := []string{"From: a@example.com\r\n"}
	d := &Signature{Version: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := d.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"", "DKIM1", "DKIM2", "dkim1", "DKIM1.0"} {
		for _, source := range []string{"explicit", "cache", "DNS"} {
			t.Run(fmt.Sprintf("%s/%s", version, source), func(t *testing.T) {
				candidate := *dk
				candidate.Version = version
				if source == "cache" {
					data, err := json.Marshal(candidate)
					if err != nil {
						t.Fatal(err)
					}
					candidate = domainkey.DomainKey{}
					if err := json.Unmarshal(data, &candidate); err != nil {
						t.Fatal(err)
					}
				}
				parsed, err := ParseSignature("DKIM-Signature: " + d.String() + "\r\n")
				if err != nil {
					t.Fatal(err)
				}
				if source == "DNS" {
					record := "k=ed25519; p=" + dk.PublicKey
					if version != "" {
						record = "v=" + version + "; " + record
					}
					parsed.VerifyWithResolver(headers, d.BodyHash, nil, keyVersionResolver{record})
				} else {
					parsed.Verify(headers, d.BodyHash, &candidate)
				}
				want := VerifyStatusPass
				if version != "" && version != "DKIM1" {
					want = VerifyStatusPermErr
					if !errors.Is(parsed.VerifyResult.Error(), domainkey.ErrInvalidVersion) {
						t.Fatalf("invalid version error lost: %v", parsed.VerifyResult.Error())
					}
				}
				if parsed.VerifyResult.Status() != want {
					t.Fatalf("status=%s want=%s", parsed.VerifyResult.Status(), want)
				}
			})
		}
	}
}
