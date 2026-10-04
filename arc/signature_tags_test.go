package arc

import (
	"crypto"
	"strings"
	"testing"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/canonical"
	"github.com/masa23/mmauth/internal/header"
)

func TestARCSignatureRequiredTags(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		required  []string
		parse     func(string) error
	}{
		{"AMS", "ARC-Message-Signature: i=1; a=rsa-sha256; bh=AAAA; d=example.com; h=from; s=s; b=AAAA", []string{"i", "a", "bh", "d", "h", "s", "b"}, func(s string) error { _, e := ParseARCMessageSignature(s); return e }},
		{"AS", "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=s; b=AAAA", []string{"i", "a", "cv", "d", "s", "b"}, func(s string) error { _, e := ParseARCSeal(s); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.parse(tc.raw + ";\r\n"); e != nil {
				t.Fatal(e)
			}
			for _, tag := range tc.required {
				t.Run("missing/"+tag, func(t *testing.T) {
					fields := strings.Split(strings.SplitN(tc.raw, ": ", 2)[1], "; ")
					var kept []string
					for _, field := range fields {
						if !strings.HasPrefix(field, tag+"=") {
							kept = append(kept, field)
						}
					}
					raw := strings.SplitN(tc.raw, ": ", 2)[0] + ": " + strings.Join(kept, "; ")
					if e := tc.parse(raw); e == nil {
						t.Fatal("missing required tag accepted")
					}
				})
				t.Run("duplicate/"+tag, func(t *testing.T) {
					if e := tc.parse(tc.raw + "; " + tag + "=AAAA"); e == nil {
						t.Fatal("duplicate tag accepted")
					}
				})
				if tag != "b" {
					t.Run("empty/"+tag, func(t *testing.T) {
						name, body, _ := strings.Cut(tc.raw, ": ")
						fields := strings.Split(body, "; ")
						for i, field := range fields {
							if strings.HasPrefix(field, tag+"=") {
								fields[i] = tag + "="
							}
						}

						if e := tc.parse(name + ": " + strings.Join(fields, "; ")); e == nil {
							t.Fatal("empty required tag accepted")
						}
					})
				}
			}
			for _, suffix := range []string{"; a=rsa-sha1", "; x-custom=one; x-custom=two", "; malformed", "; =value"} {
				if e := tc.parse(tc.raw + suffix); e == nil {
					t.Errorf("invalid suffix %q accepted", suffix)
				}
			}
			if e := tc.parse(tc.raw + "; x-custom=one"); e != nil {
				t.Fatalf("unknown tag rejected: %v", e)
			}
			if e := tc.parse(strings.Replace(tc.raw, "b=AAAA", "b=", 1)); e != nil {
				t.Fatalf("signing placeholder rejected: %v", e)
			}
		})
	}
}

func TestARCSignedMissingAndDuplicateAlgorithm(t *testing.T) {
	key := testKeys.RSAPrivateKey
	dk := &domainkey.DomainKey{PublicKey: testKeys.RSAPublicKeyBase64}
	const bh = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	sign := func(h []string) string {
		v, e := header.SignerWithOmitLastCRLF(h, key, canonical.Relaxed, crypto.SHA256, true)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, target := range []string{"control", "AMS missing a", "AS missing a", "AMS duplicate a", "AS duplicate a"} {
		t.Run(target, func(t *testing.T) {
			from := "From: a@example.com\r\n"
			aar := "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n"
			ams := "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s; h=From; bh=" + bh + "; b="
			seal := "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=s; cv=none; b="
			if target == "AMS missing a" {
				ams = strings.Replace(ams, "a=rsa-sha256; ", "", 1)
			}
			if target == "AS missing a" {
				seal = strings.Replace(seal, "a=rsa-sha256; ", "", 1)
			}
			if target == "AMS duplicate a" {
				ams = strings.Replace(ams, "a=rsa-sha256; ", "a=rsa-sha1; a=rsa-sha256; ", 1)
			}
			if target == "AS duplicate a" {
				seal = strings.Replace(seal, "a=rsa-sha256; ", "a=rsa-sha1; a=rsa-sha256; ", 1)
			}
			ams += sign([]string{from, ams + "\r\n"}) + "\r\n"
			seal += sign([]string{aar, ams, seal + "\r\n"}) + "\r\n"
			headers := []string{from, aar, ams, seal}
			sigs, e := ParseARCHeaders(headers)
			if target != "control" {
				if e == nil || sigs.GetVerifyResult() != VerifyStatusFail {
					t.Fatalf("malformed signed chain accepted: error=%v status=%s", e, sigs.GetVerifyResult())
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			sigs.GetInstance(1).Verify(headers, bh, dk)
			if sigs.GetVerifyResult() != VerifyStatusPass {
				t.Fatal(sigs.GetVerifyResultString())
			}
		})
	}
}
