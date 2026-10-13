package arc

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRFC8617MalformedAARPayloadDoesNotInvalidateSignedChain(t *testing.T) {
	key, domainKey := regressionARCKey(t)
	headers := []string{"From: a@example.com\r\n"}
	ams := &ARCMessageSignature{InstanceNumber: 1, Domain: "example.com", Selector: "s", Canonicalization: "relaxed/relaxed", BodyHash: "Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4dTFz++ji4M="}
	if err := ams.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	// The trailing semicolon violates RFC 8601, but RFC 8617 §3.4 says the
	// assessment syntax cannot make an otherwise valid ARC chain fail.
	headers = append(headers, "ARC-Authentication-Results: i=1; example.com; dkim=pass;\r\n", "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &ARCSeal{InstanceNumber: 1, Domain: "example.com", Selector: "s", ChainValidation: ChainValidationResultNone}
	if err := seal.Sign(headers, key); err != nil {
		t.Fatal(err)
	}
	headers = append(headers, fmt.Sprintf("ARC-Seal: %s\r\n", seal.String()))
	chain := regressionVerify(t, headers, domainKey)
	if got := chain.GetVerifyResult(); got != VerifyStatusPass {
		t.Fatalf("signed chain with malformed assessment = %s, want pass", got)
	}
}

func TestRFC8617AARFoldedCommentsAndQuotedSemicolon(t *testing.T) {
	const raw = "ARC-Authentication-Results: (edge) i=1 (hop);\r\n" +
		" mx.example.com; dkim=pass (checked; trusted) header.i=\"a;tag@example.com\";\r\n" +
		" spf=pass smtp.mailfrom=example.com\r\n"
	aar, err := ParseARCAuthenticationResults(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"dkim=pass (checked; trusted) header.i=\"a;tag@example.com\"",
		"spf=pass smtp.mailfrom=example.com",
	}
	if aar.InstanceNumber != 1 || aar.AuthServId != "mx.example.com" || !reflect.DeepEqual(aar.Results, want) {
		t.Fatalf("parsed AAR=%+v, want results=%v", aar, want)
	}
	if aar.Raw() != raw {
		t.Fatal("signed raw AAR was changed")
	}
	encoded := ARCAuthenticationResults{InstanceNumber: 1, AuthServId: aar.AuthServId, Results: aar.Results}.String()
	parsed, err := ParseARCAuthenticationResults("ARC-Authentication-Results: " + encoded + "\r\n")
	if err != nil || !reflect.DeepEqual(parsed.Results, want) {
		t.Fatalf("AAR round trip=%+v, error=%v", parsed, err)
	}
}

func TestRFC8617AARNoResultAndMalformedCFWS(t *testing.T) {
	aar, err := ParseARCAuthenticationResults("ARC-Authentication-Results: i=2; mx.example.com; none\r\n")
	if err != nil || aar.InstanceNumber != 2 || aar.AuthServId != "mx.example.com" || !reflect.DeepEqual(aar.Results, []string{"none"}) {
		t.Fatalf("none result=%+v, error=%v", aar, err)
	}
	serialized := (ARCAuthenticationResults{InstanceNumber: 2, AuthServId: "mx.example.com"}).String()
	if !strings.HasSuffix(serialized, "; none") {
		t.Fatalf("empty assessment serialized as %q", serialized)
	}
	for _, raw := range []string{
		"ARC-Authentication-Results: i=1; mx.example.com; dkim=pass (unterminated\r\n",
		"ARC-Authentication-Results: i=1; mx.example.com; dkim=pass header.i=\"unterminated\r\n",
	} {
		if _, err := ParseARCAuthenticationResults(raw); err == nil {
			t.Fatalf("malformed CFWS accepted: %q", raw)
		}
	}
}

func TestRFC8617AARChainRejectsInvalidEnvelope(t *testing.T) {
	for _, raw := range []string{
		"ARC-Authentication-Reſults: i=1; mx.example.com; none\r\n",
		" ARC-Authentication-Results: i=1; mx.example.com; none\r\n",
		"ARC-Authentication-Results\v: i=1; mx.example.com; none\r\n",
		"ARC-Authentication-Results: i=1\v; mx.example.com; none\r\n",
		"ARC-Authentication-Results: i=1; mx.example.com; broken\x00payload\r\n",
		"ARC-Authentication-Results: i=1; mx.example.com; broken\r\nX-Injected: yes\r\n",
		"ARC-Authentication-Results: i=1; mx.example.com; broken\n",
	} {
		if _, err := parseAARForChain(raw); err == nil {
			t.Errorf("accepted malformed AAR envelope %q", raw)
		}
	}
	if _, err := parseAARForChain("ARC-Authentication-Results: i=1; mx.example.com; broken\r\n continuation\r\n"); err != nil {
		t.Fatalf("valid folded malformed payload rejected: %v", err)
	}
}

func TestRFC8617ARCInstanceIgnoresUnicodeLookalikeField(t *testing.T) {
	raw := "ARC-ſeal: i=2; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n"
	if _, ok := arcHeaderInstance(raw); ok {
		t.Fatal("Unicode lookalike recognized as ARC-Seal")
	}
	if isLaterARCHeader(raw, 1) {
		t.Fatal("Unicode lookalike recognized as a later ARC-Seal")
	}
	for _, raw := range []string{
		"ARC-Seal: I=2; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n",
		"ARC-Seal: ı=2; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n",
		"ARC-Seal: i=+2; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n",
		"ARC-Seal: i=002; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n",
		"ARC-Seal: i=1 2; a=rsa-sha256; cv=pass; d=example.com; s=s; b=AAAA\r\n",
	} {
		if _, ok := arcHeaderInstance(raw); ok || isLaterARCHeader(raw, 1) {
			t.Fatalf("unregistered instance tag recognized: %q", raw)
		}
	}
}
