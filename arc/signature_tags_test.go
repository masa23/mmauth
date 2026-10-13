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
			if e := tc.parse(strings.Replace(tc.raw, "S", "ſ", 1)); e == nil {
				t.Error("Unicode field name lookalike accepted")
			}
			if e := tc.parse(tc.raw + ";\r\n"); e != nil {
				t.Fatal(e)
			}
			if e := tc.parse(strings.Replace(tc.raw, "i=1; a=rsa-sha256", "a=rsa-sha256; i=1", 1)); e == nil {
				t.Error("instance tag outside first position accepted")
			}
			for _, number := range []string{"+1", "0001", "00", "51"} {
				if e := tc.parse(strings.Replace(tc.raw, "i=1;", "i="+number+";", 1)); e == nil {
					t.Errorf("invalid ARC instance %q accepted", number)
				}
			}
			if e := tc.parse(strings.Replace(tc.raw, "i=1;", "i=01;", 1)); e != nil {
				t.Errorf("RFC 8617 1*2DIGIT position 01 rejected: %v", e)
			}
			for _, timestamp := range []string{"-1", "+1", "1234567890123", "1 2"} {
				if e := tc.parse(tc.raw + "; t=" + timestamp); e == nil {
					t.Errorf("invalid ARC timestamp %q accepted", timestamp)
				}
			}
			if e := tc.parse(tc.raw + "; t=123456789012"); e != nil {
				t.Errorf("valid 12-digit ARC timestamp rejected: %v", e)
			}
			if e := tc.parse(strings.Replace(tc.raw, ": ", ": ; ", 1)); e == nil {
				t.Error("leading empty tag accepted")
			}
			fieldName, _, _ := strings.Cut(tc.raw, ":")
			for _, badName := range []string{" " + fieldName, fieldName + " "} {
				if e := tc.parse(strings.Replace(tc.raw, fieldName+":", badName+":", 1)); e == nil {
					t.Fatalf("invalid field name %q accepted", badName)
				}
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
			for _, suffix := range []string{"; a=rsa-sha1", "; x-custom=one; x-custom=two", "; malformed", "; =value", ";;", "; ; x=one", "; 1x=one", "; x-y=one", "; x$=one", "; x=" + string([]byte{0xff})} {
				if e := tc.parse(tc.raw + suffix); e == nil {
					t.Errorf("invalid suffix %q accepted", suffix)
				}
			}
			if e := tc.parse(strings.Replace(tc.raw, "a=rsa-sha256", "A=rsa-sha256", 1)); e == nil {
				t.Error("case-distinct unknown A tag replaced required a tag")
			}
			if e := tc.parse(tc.raw + "; X=one; x=two"); e != nil {
				t.Fatalf("case-distinct unknown tags rejected: %v", e)
			}
			if e := tc.parse(tc.raw + "; x_custom=one"); e != nil {
				t.Fatalf("unknown tag rejected: %v", e)
			}
			if e := tc.parse(tc.raw + "; x=é"); e != nil {
				t.Fatalf("RFC 8617 UTF-8 tag value rejected: %v", e)
			}
			for _, pair := range [][2]string{{"d=example.com", "d=example .com"}, {"s=s", "s=s s"}} {
				if e := tc.parse(strings.Replace(tc.raw, pair[0], pair[1], 1)); e == nil {
					t.Errorf("invalid ARC identifier %q accepted", pair[1])
				}
			}
			if e := tc.parse(strings.Replace(tc.raw, "b=AAAA", "b=", 1)); e != nil {
				t.Fatalf("signing placeholder rejected: %v", e)
			}
		})
	}
}

func TestARCSignatureRejectsTrailingControlCharacter(t *testing.T) {
	for _, raw := range []string{
		"ARC-Message-Signature: i=1; a=rsa-sha256; bh=AAAA; d=example.com; h=from; s=s; b=AAAA\v\r\n",
		"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=s; b=AAAA\v\r\n",
	} {
		if strings.HasPrefix(raw, "ARC-Seal:") {
			if _, err := ParseARCSeal(raw); err == nil {
				t.Errorf("accepted malformed seal %q", raw)
			}
		} else if _, err := ParseARCMessageSignature(raw); err == nil {
			t.Errorf("accepted malformed message signature %q", raw)
		}
	}
}

func TestRFC8617ARCSignedHeaderNamesPreserveInternalWhitespace(t *testing.T) {
	const prefix = "ARC-Message-Signature: i=1; a=rsa-sha256; bh=AAAA; d=example.com; h="
	const suffix = "; s=s; b=AAAA\r\n"
	for _, value := range []string{"From:Bad Name", "Fr om", "From::Subject", "From:é"} {
		if _, err := ParseARCMessageSignature(prefix + value + suffix); err == nil {
			t.Errorf("invalid h= value %q accepted", value)
		}
	}
	parsed, err := ParseARCMessageSignature(prefix + "From \r\n : \r\n Subject" + suffix)
	if err != nil || parsed.Headers != "From:Subject" {
		t.Fatalf("valid FWS around h= delimiter: parsed=%+v, error=%v", parsed, err)
	}
}

func TestRFC8617ARCULabelSigningIdentifiersUseALabelDNS(t *testing.T) {
	key, domainKey := regressionARCKey(t)
	oldResolver := domainkey.DefaultResolver
	t.Cleanup(func() { domainkey.DefaultResolver = oldResolver })
	lookups := 0
	domainkey.DefaultResolver = func(name string) ([]string, error) {
		if name != "xn--bcher-kva._domainkey.xn--bcher-kva.example" {
			t.Fatalf("unexpected ARC key lookup %q", name)
		}
		lookups++
		return []string{"v=DKIM1; k=ed25519; p=" + domainKey.PublicKey}, nil
	}
	const bodyHash = "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="
	headers := []string{"From: a@example.com\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "bücher.example", Selector: "bücher", Canonicalization: "relaxed/relaxed", BodyHash: bodyHash}
	if err := ams.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "bücher.example", Selector: "bücher", ChainValidation: ChainValidationResultNone}
	if err := seal.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, "ARC-Seal: "+seal.String()+"\r\n")
	chain, err := ParseARCHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	chain.GetInstance(1).VerifyWithKeys(headers, bodyHash, nil, nil)
	if lookups != 2 || chain.GetVerifyResult() != VerifyStatusPass {
		t.Fatalf("U-label ARC verification: lookups=%d status=%s", lookups, chain.GetVerifyResult())
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
