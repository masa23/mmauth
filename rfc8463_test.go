package mmauth

import (
	"crypto"
	"strings"
	"testing"

	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
)

const rfc8463EdRecord = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
const rfc8463RSARecord = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"

const rfc8463Message = `DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.

`

func rfc8463MessageWithCRLF() string {
	return strings.ReplaceAll(rfc8463Message, "\n", "\r\n")
}

// RFC 8463 Appendix A.3 signs one message with independent Ed25519 and RSA
// selectors. The inline RFC example uses LF and is converted to CRLF.
func TestRFC8463AppendixASignedMessage(t *testing.T) {
	message := rfc8463MessageWithCRLF()
	keys := map[string]string{"brisbane": rfc8463EdRecord, "test": rfc8463RSARecord}

	for _, tc := range []struct {
		name    string
		message string
		want    map[string]dkim.VerifyStatus
	}{
		{"original", message, map[string]dkim.VerifyStatus{"brisbane": dkim.VerifyStatusPass, "test": dkim.VerifyStatusPass}},
		{"modified header", strings.Replace(message, "Joe SixPack", "Eve SixPack", 1), map[string]dkim.VerifyStatus{"brisbane": dkim.VerifyStatusFail, "test": dkim.VerifyStatusFail}},
		{"modified body", strings.Replace(message, "We lost the game.", "We won the game.", 1), map[string]dkim.VerifyStatus{"brisbane": dkim.VerifyStatusFail, "test": dkim.VerifyStatusFail}},
		{"modified Ed25519 signature", strings.Replace(message, "b=/gCrinpc", "b=AgCrinpc", 1), map[string]dkim.VerifyStatus{"brisbane": dkim.VerifyStatusFail, "test": dkim.VerifyStatusPass}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMMAuth()
			if _, err := m.Write([]byte(tc.message)); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			sigs := *m.AuthenticationHeaders.DKIMSignatures
			if len(sigs) != 2 {
				t.Fatalf("DKIM signatures=%d, want 2", len(sigs))
			}
			for _, sig := range sigs {
				record, ok := keys[sig.Selector]
				if !ok {
					t.Fatalf("unexpected selector %q", sig.Selector)
				}
				key, err := domainkey.ParseDomainKeyRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				bodyHash := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{Body: CanonicalizationRelaxed, Algorithm: crypto.SHA256})
				sig.Verify(m.Headers, bodyHash, &key)
				if got := sig.VerifyResult.Status(); got != tc.want[sig.Selector] {
					t.Fatalf("%s verification=%s, want %s: %v", sig.Algorithm, got, tc.want[sig.Selector], sig.VerifyResult.Error())
				}
			}
		})
	}
}
