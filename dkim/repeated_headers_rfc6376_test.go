package dkim

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/masa23/mmauth/domainkey"
)

func TestRFC6376RepeatedHeaderSelectionWithIndependentSignature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	publicKey := &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	const from = "From: a@example.com\r\n"
	const older = "Subject: older\r\n"
	const newer = "Subject: newer\r\n"
	headers := []string{from, older, newer}
	const bare = "DKIM-Signature: v=1; a=ed25519-sha256; c=simple/simple; d=example.com; s=s; h=Subject:From:Subject; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; b="
	// h= selects the bottommost unused matching field for each entry.
	digest := sha256.Sum256([]byte(newer + from + older + bare))
	raw := bare + base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest[:])) + "\r\n"
	for _, tc := range []struct {
		name    string
		headers []string
		want    VerifyStatus
	}{
		{"original", headers, VerifyStatusPass},
		{"swapped repeated fields", []string{from, newer, older}, VerifyStatusFail},
		{"changed From", []string{"From: b@example.com\r\n", older, newer}, VerifyStatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := ParseSignature(raw)
			if err != nil {
				t.Fatal(err)
			}
			sig.Verify(tc.headers, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", publicKey)
			if result := sig.VerifyResult; result.Status() != tc.want {
				t.Fatalf("verification=%s, want %s: %v", result.Status(), tc.want, result.Error())
			}
		})
	}
}
