package header

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/masa23/mmauth/internal/canonical"
)

var testRSAPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgUTPX3OM3V/Au
mWjNEgXP5/s91oBA4blrWQ7j3o1Oos2++RsMMAgkbeMAAUD+k+RcDnBHMiYO5S8y
ae6u/ggVkl++VMQdp0FuClCOAKBKepRchhrVTgQt4F8QcVUFXSVQhNtn2QEaMn3Y
jeogWvc9CTKxLr9h8mWkEnQKsLc+VQZ+qO2cRDWklz36hk2YiLLDYKsw51mqKKNs
3xm5zaOo8GXehb0Ilppy/41lS6gG45E6yYfr+ZUABgVrZFeKg4q3bXiE8fSgWwTO
P0IsOrCp1tVoGkxTiH06kbU+0/kMiRs0vy9Mp+MMcqhu8NNjfnUlly1RNandXCi8
BZp0KOclAgMBAAECggEAHlDcteA+U1PcxmMaL1VOJg+fMgVjAWHt9z/DEhIetJUS
xR9EHxziHUluWKzkBoAe+c19K+luyvhJ4YWorgy5qKKiWlKbN2ROeimXLBMwPIVL
kueFIXr8TVSVhX1472e6y6wj9VJS5ApSQ+YqNO4evLsFi/3kEPiOgeU/bloWfMG4
twwe5scyVlcDiiBwVFBSnoSQKR3szoGIsvr4gH4QQGHWnn+9S8o+ujOCmdcHpOjF
5QJMjmBQjTgujBFQJA5B0ITSsT9wfSOKEdyBKphzfU2cbFUUfUwWF6WS8g1vVC76
3+NmiB06UcNGVFl4vID+zG6Y2CHiScfXBAmpXgepoQKBgQDLcnzDcZTAPdAQnU5U
QvcTavNSh3rh7W0/vMmOeXooqKSqTLzGXSnIQjuNIo2oIVP2cLsv3p1d73Qupk9g
S9USC3Zac2i6tSbKUxPBAyBlzwCl4aFLpq1MV/+G+/3E7+3EOWOzqTXlvMOxpTZT
pSWsXL4fpdkaJr/XPWnWxl06OQKBgQDJup9uS4cXwMXGaFpmQ0YqGcAlQOtIErLa
mTlPxU2T8gUl9z5xcV5EmXMSWU6bpoH5pmCw52VI8Ue02KBKsNfz9M8J8oG7ttvq
jTZOtutw450d0tSejCpMbRT3rD2ajosfes3kdhE0DVJLrLW0cInBYW5/8tGykXzX
b5j87OGETQKBgBCmyjdk8Hvbk1AI0ARthrN8KXYzyIb9W9e/p++VWb5CL1gQ99J0
hZrycNVYYqfEMo8VIv0EB3VMyAGZcx26lzHm5kT49TVy5j3hFtjRXLF4g+EP2pfK
iJybBzsRHPAlgxxwZgyqaNLo5EuB7jRia/bzkEwe0uolCcagLC18Bt1hAoGAXb/e
QgrVsINFJozuniHbpMss0eNWtLsD5bVZvinKgNvz6o35tgziq2zI3pkkgA+kzdm1
i+Et3/VJxtD5xVxkMBrwcQYDprI3h8yylWhLCL6vEOIfL8OiELyNBwFD6+Uc4LdY
ojkAi7k5KrQMCdxXGMjn6ox1SdB1PUW+yqRnte0CgYB/QZbQFNh4QNwvu8iEX+Hf
DPWNXHRThsvznuZTQdg6mmI3uNb7rdS5RF0raw8S8cmtTtFsJ9xjhlZAyC1fwpO6
Xh472j/rkZiJrHbqPzzl3oyUCwCtTVrjBp/fuHa9HMbJQHAhUIEtzAKT0mg5mylY
1BG8h/cStiof/9746AZMIw==
-----END PRIVATE KEY-----
`

var testED25519PrivateKey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL0sK/kwzKr3mdeGnWgN/rtX4UKYgK90oA8DNL9ebBME
-----END PRIVATE KEY-----
`

type testKey struct {
	RSAPrivateKey     *rsa.PrivateKey
	ED25519PrivateKey ed25519.PrivateKey
}

func (k *testKey) getPrivateKey(keyType string) crypto.Signer {
	switch keyType {
	case "rsa":
		return k.RSAPrivateKey
	case "ed25519":
		return k.ED25519PrivateKey
	default:
		return nil
	}
}

var testKeys = testKey{}

func TestMain(m *testing.M) {
	// RSA
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	if block == nil {
		log.Fatalf("failed to decode RSA private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse RSA private key: %s", err)
	}
	testKeys.RSAPrivateKey = priv.(*rsa.PrivateKey)
	// ED25519
	block, _ = pem.Decode([]byte(testED25519PrivateKey))
	if block == nil {
		log.Fatalf("failed to decode ED25519 private key")
	}
	priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ED25519 private key: %s", err)
	}
	testKeys.ED25519PrivateKey = priv.(ed25519.PrivateKey)

	os.Exit(m.Run())
}

func TestSigner(t *testing.T) {
	cases := []struct {
		name    string
		keyType string
		headers []string
		canon   canonical.Canonicalization
		want    string
		wantErr error
	}{
		{
			name:    "relaxed rsa",
			keyType: "rsa",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; b=\r\n",
			},
			canon:   canonical.Relaxed,
			want:    "McwKSXaD2OFojyuoBVqjkzyIRb85nR/AOexdZfkny5+1PAS24JP4vJNWjjM9c3eUarqRn8r9/zc4tUgeBzWG5y0lhxii/QGEfnuQIGOdk0qXE6TKyTNqb2vKKlQEW7kdMqeLZRL41HCVvVBSctN4eiTiXfv5n0rUOIrGeMvvhbHcc4d/cm6Ikn5n3xndiAxCohCTR7h5X2AmoG4Vc2FcLOc4DEQAulW9H1INBFBlZcgzQgLQ4emmH0v1vAQdAxR7Mu2X4JZaAtIVa/LRJd37TtH+jTU5mnzJjJShmX1Rt6voWC4Qp2+Mqc5XQm3M2N+Nm7yFycKUVu7Ho/d+ayHlEQ==",
			wantErr: nil,
		},
		{
			name:    "simple rsa",
			keyType: "rsa",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=simple/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; b=\r\n",
			},
			canon:   canonical.Simple,
			want:    "MMfmJ0ZZLLG3Is/t4PKTXM0xPfjAHplc3nGr+PL8s2T2vJ08FITdZOrxgQvAmPteNxwgcx1JnBkFnhe+0dtohZPCZAz4825Cpo4tjHmOHswALJ1hFWoaFGrpF53EQYhPN6MUrlVXEurIE5zxA1O7EuRUE7eyYahEKTyA1wJCYE/2TpYCZh35R4kCHXRLlih2vYBjI6YTlNS5zLSjUANCCJ1VrNm5IKLt72OZJ2TkXBFtheKDfT2nCsorroTr/d44VRHzBPQEGx7zPqcA8eibFoG+biKciN0h9YO3KFyaOuvSkKcyFka/eVscPHOsAtUeyz01qfn0TSEYHRqSbDvlpg==",
			wantErr: nil,
		},
		{
			name:    "relaxed ed25519",
			keyType: "ed25519",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com;\r\n\ts=selector; t=1728300596;\r\n\tbh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=;\r\n\th=Date:From:To:Subject;\r\n\tb=\r\n",
			},
			canon:   canonical.Relaxed,
			want:    "TWR6qXPswzKR7CLAZDE1itlYdl7V2mlC7CGrSAZLO9Zevutv3+mvX600q4yTTWHsrbBt0Ys20yyjzmqach8eBQ==",
			wantErr: nil,
		},
		{
			name:    "simple ed25519",
			keyType: "ed25519",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"DKIM-Signature: v=1; a=ed25519-sha256; c=simple/simple; d=example.com;\r\n\ts=selector; t=1728300288;\r\n\tbh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=;\r\n\th=Date:From:To:Subject;\r\n\tb=\r\n",
			},
			canon:   canonical.Simple,
			want:    "5PTuUjk5Bcq0Qml+qQR2plKonmLRagpy8/60XEnPod0MmwWkmppf4he++gu6p2IwOum5PGdc7zRetp/W+pz5Cg==",
			wantErr: nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var hashAlgo crypto.Hash
			switch tt.keyType {
			case "rsa":
				hashAlgo = crypto.SHA256
			case "ed25519":
				hashAlgo = crypto.Hash(0)
			}
			got, err := Signer(tt.headers, testKeys.getPrivateKey(tt.keyType), tt.canon, hashAlgo)
			if err != tt.wantErr {
				t.Errorf("headerSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("headerSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHeaderCanonicalization(t *testing.T) {
	testCases := []struct {
		name       string
		input      string
		wantHeader canonical.Canonicalization
		wantBody   canonical.Canonicalization
		wantErr    bool
	}{
		{
			name:       "simple/simple",
			input:      "simple/simple",
			wantHeader: canonical.Simple,
			wantBody:   canonical.Simple,
			wantErr:    false,
		},
		{
			name:       "relaxed/relaxed",
			input:      "relaxed/relaxed",
			wantHeader: canonical.Relaxed,
			wantBody:   canonical.Relaxed,
			wantErr:    false,
		},
		{
			name:       "simple/relaxed",
			input:      "simple/relaxed",
			wantHeader: canonical.Simple,
			wantBody:   canonical.Relaxed,
			wantErr:    false,
		},
		{
			name:       "relaxed/simple",
			input:      "relaxed/simple",
			wantHeader: canonical.Relaxed,
			wantBody:   canonical.Simple,
			wantErr:    false,
		},
		{
			name:       "simple",
			input:      "simple",
			wantHeader: canonical.Simple,
			wantBody:   canonical.Simple,
			wantErr:    false,
		},
		{
			name:       "relaxed",
			input:      "relaxed",
			wantHeader: canonical.Relaxed,
			wantBody:   canonical.Simple,
			wantErr:    false,
		},
		{
			name:       "empty",
			input:      "",
			wantHeader: canonical.Simple,
			wantBody:   canonical.Simple,
			wantErr:    false,
		},
		{
			name:       "invalid header",
			input:      "invalid/simple",
			wantHeader: "",
			wantBody:   "",
			wantErr:    true,
		},
		{
			name:       "invalid body",
			input:      "simple/invalid",
			wantHeader: "",
			wantBody:   "",
			wantErr:    true,
		},
		{
			name:       "both invalid",
			input:      "invalid/invalid",
			wantHeader: "",
			wantBody:   "",
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header, body, err := ParseHeaderCanonicalization(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseHeaderCanonicalization() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if header != tc.wantHeader {
				t.Errorf("ParseHeaderCanonicalization() header = %v, want %v", header, tc.wantHeader)
			}
			if body != tc.wantBody {
				t.Errorf("ParseHeaderCanonicalization() body = %v, want %v", body, tc.wantBody)
			}
		})
	}
}

func TestParseHeaderParams(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{
			name:  "normal",
			input: "a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
			expect: map[string]string{
				"a":  "rsa-sha256",
				"bh": "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				"c":  "relaxed/relaxed",
				"d":  "example.jp",
				"h":  "Date:From:To:Subject:Message-Id",
				"s":  "rs20240124",
				"t":  "1706971004",
				"v":  "1",
				"b":  "vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
			},
		},
		{
			name:   "empty",
			input:  "",
			expect: map[string]string{},
		},
		{
			name:  "no-value",
			input: "a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=",
			expect: map[string]string{
				"a":  "rsa-sha256",
				"bh": "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				"c":  "relaxed/relaxed",
				"d":  "example.jp",
				"h":  "Date:From:To:Subject:Message-Id",
				"s":  "rs20240124",
				"t":  "1706971004",
				"v":  "1",
				"b":  "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHeaderParams(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}

func TestDeleteSignature(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "test1",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=signature!!",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=",
		},
		{
			name:   "test2",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=signature!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
		},
		{
			name:   "test3",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=sig\r\n\tnatu\r\n re!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
		},
		{
			name:   "test4",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1\r\nEvx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=sig\r\n\tnatu\r\n re!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1\r\n",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1\r\nEvx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeleteSignature(tc.input)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%s, expect=%s", got, tc.expect)
			}
		})
	}
}

func TestExtractHeadersDKIM(t *testing.T) {
	testCases := []struct {
		name    string
		list    []string
		headers []string
		expect  []string
	}{
		{
			name: "test1",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
			},
		},
		{
			name: "test2",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge\r\n",
			},
		},
		{
			name: "test3",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge1\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
		{
			name: "test4",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Hoge: hoge1\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHeadersDKIM(tc.headers, tc.list)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}

func TestExtractHeadersDKIM_PlanCases(t *testing.T) {
	// Case A: `h=` に同名ヘッダが重複する
	t.Run("Case A: Duplicate headers in h=", func(t *testing.T) {
		headers := []string{
			"From: A <a@example.com>\r\n",
			"From: B <b@example.com>\r\n",
			"To: x@example.com\r\n",
		}
		keys := []string{"from", "from", "to"}
		expect := []string{
			"From: B <b@example.com>\r\n",
			"From: A <a@example.com>\r\n",
			"To: x@example.com\r\n",
		}
		got := ExtractHeadersDKIM(headers, keys)
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("unexpected result: got=%v, expect=%v", got, expect)
		}
	})

	// Case B: 存在しないヘッダ名（null string扱い）
	t.Run("Case B: Non-existent header names (null string treatment)", func(t *testing.T) {
		headers := []string{
			"From: A <a@example.com>\r\n",
		}
		keys := []string{"cc", "from", "reply-to"}
		expect := []string{
			"From: A <a@example.com>\r\n",
		}
		got := ExtractHeadersDKIM(headers, keys)
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("unexpected result: got=%v, expect=%v", got, expect)
		}
	})

	// Case C: 大文字小文字・空白耐性
	t.Run("Case C: Case and whitespace tolerance", func(t *testing.T) {
		headers := []string{
			"Subject: hi\r\n",
			"subject: hi2\r\n",
		}
		keys := []string{"  SUBJECT ", " subject "}
		expect := []string{
			"subject: hi2\r\n",
			"Subject: hi\r\n",
		}
		got := ExtractHeadersDKIM(headers, keys)
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("unexpected result: got=%v, expect=%v", got, expect)
		}
	})
}

func TestExtractHeadersARC(t *testing.T) {
	testCases := []struct {
		name    string
		list    []string
		headers []string
		expect  []string
	}{
		{
			name: "test1",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
			},
		},
		{
			name: "test2",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge\r\n",
			},
		},
		{
			name: "test3",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge1\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
		{
			name: "test4",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Hoge: hoge1\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHeadersDKIM(tc.headers, tc.list)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}
func TestRemoveDuplicates(t *testing.T) {
	testCases := []struct {
		input  []string
		expect []string
	}{
		{
			input:  []string{"a", "b", "c", "d", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
		{
			input:  []string{"a", "b", "c", "d", "e", "a", "b", "c", "d", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
		{
			input:  []string{"a", "b", "b", "c", "d", "e", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
	}

	for _, tc := range testCases {
		got := RemoveDuplicates(tc.input)
		if !reflect.DeepEqual(got, tc.expect) {
			t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
		}
	}
}

func TestParseAddress(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedDomain string
	}{
		{
			name:           "Valid input",
			input:          "John Doe <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Valid input with multibyte username",
			input:          "John Doe <テスト@example.com>",
			expectedDomain: "テスト@example.com",
		},
		{
			name:           "Vaild input with ISO-2022-JP",
			input:          "=?ISO-2022-JP?B?GyRCRnxLXDhsJDUkTxsoQg==?= <test@example.jp>",
			expectedDomain: "test@example.jp",
		},
		{
			name:           "Valid input with simple address",
			input:          "test@example.net",
			expectedDomain: "test@example.net",
		},
		{
			name:           "Valid input with simple address",
			input:          "<test@example.net>",
			expectedDomain: "test@example.net",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John Doe\" <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John<aaa@aa.com>Doe\" <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "hoge <\"ho ge\"@example.com>",
			expectedDomain: "\"ho ge\"@example.com",
		},
		{
			name:           "Invalid input with duble quote address and atmark",
			input:          "John Doe <\"john.doe@aa\"@example.com>",
			expectedDomain: "\"john.doe@aa\"@example.com",
		},
		{
			name:           "Valid input if the string is empty",
			input:          "",
			expectedDomain: "",
		},
		{
			name:           "Valid input if the string is empty2",
			input:          "Maria <>",
			expectedDomain: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain := ParseAddress(tc.input)

			if domain != tc.expectedDomain {
				t.Errorf("Expected domain: %s, but got: %s", tc.expectedDomain, domain)
			}
		})
	}
}

func TestParseAddressDomain(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedDomain string
		expectedErr    error
	}{
		{
			name:           "Valid input",
			input:          "John Doe <john.doe@example.com>",
			expectedDomain: "example.com",
			expectedErr:    nil,
		},
		{
			name:           "Valid input with multibyte username",
			input:          "John Doe <テスト@example.com>",
			expectedDomain: "example.com",
			expectedErr:    nil,
		},
		{
			name:           "Vaild input with ISO-2022-JP",
			input:          "=?ISO-2022-JP?B?GyRCRnxLXDhsJDUkTxsoQg==?= <test@example.jp>",
			expectedDomain: "example.jp",
		},
		{
			name:           "Valid input with simple address",
			input:          "test@example.net",
			expectedDomain: "example.net",
		},
		{
			name:           "Valid input with simple address",
			input:          "<test@example.net>",
			expectedDomain: "example.net",
		},
		{
			name:           "Valid input with simple address space",
			input:          "test@example.net",
			expectedDomain: "example.net",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John Doe\" <john.doe@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John<aaa@aa.com>Doe\" <john.doe@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "hoge <\"ho ge\"@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address and atmark",
			input:          "John Doe <\"john.doe@aa\"@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Valid input if the string is empty",
			input:          "",
			expectedDomain: "",
			expectedErr:    ErrInvalidEmailFormat,
		},
		{
			name:           "Valid input if the string is empty2",
			input:          "Maria <>",
			expectedDomain: "",
			expectedErr:    ErrInvalidEmailFormat,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain, err := ParseAddressDomain(tc.input)

			if domain != tc.expectedDomain {
				t.Errorf("Expected domain: %s, but got: %s", tc.expectedDomain, domain)
			}

			if (tc.expectedErr == nil && err != nil) || (tc.expectedErr != nil && err == nil) || (tc.expectedErr != nil && err != nil && tc.expectedErr.Error() != err.Error()) {
				t.Errorf("Expected error: %v, but got: %v", tc.expectedErr, err)
			}
		})
	}
}
