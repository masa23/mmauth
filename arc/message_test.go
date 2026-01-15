package arc

import (
	"crypto"
	"testing"

	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/internal/bodyhash"
	"github.com/masa23/mmauth/internal/canonical"
)

func TestARCMessageSignatureParse(t *testing.T) {
	testCase := []struct {
		name     string
		input    string
		expected *ARCMessageSignature
	}{
		{
			name: "simple/simple",
			input: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEz\r\n" +
				"         kkU9yAQf+lRfy1wxVJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOW\r\n" +
				"         WDBRLmhjZFM35FRzCZDledSUC/JMVQjeqA4Go1UzwB9cxh+t1S3TvuatrTsb0z0u\r\n" +
				"         ZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8M2Y5x+xoVed9Zp06\r\n" +
				"         JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA\r\n" +
				"         gvyW8Csb55+hxcTILU4ZyQ==\r\n",
			expected: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				Signature: "ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEzkkU9yAQf+lRfy1wx" +
					"VJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOWWDBRLmhjZFM35FRzCZDledSUC/JMVQje" +
					"qA4Go1UzwB9cxh+t1S3TvuatrTsb0z0uZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8" +
					"M2Y5x+xoVed9Zp06JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA" +
					"gvyW8Csb55+hxcTILU4ZyQ==",
				raw: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEz\r\n" +
					"         kkU9yAQf+lRfy1wxVJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOW\r\n" +
					"         WDBRLmhjZFM35FRzCZDledSUC/JMVQjeqA4Go1UzwB9cxh+t1S3TvuatrTsb0z0u\r\n" +
					"         ZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8M2Y5x+xoVed9Zp06\r\n" +
					"         JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA\r\n" +
					"         gvyW8Csb55+hxcTILU4ZyQ==\r\n",
			},
		},
		{
			name: "relaxed/relaxed",
			input: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1C\r\n" +
				"         TcWLKONKZYFWz3ERlTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5m\r\n" +
				"         NlNkuZPygJf0kM9JYc6wW/m7mpriEzTkYmxxSUn/2opOGAz8UiU/Tp663vo9jT7L\r\n" +
				"         sKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH465mrr0xnkiIZK2Bzn\r\n" +
				"         jqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60\r\n" +
				"         h9Jh14Pe6+KosrjrF6xqpQ==\r\n",
			expected: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				Signature: "MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1CTcWLKONKZYFWz3ER" +
					"lTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5mNlNkuZPygJf0kM9JYc6wW/m7mpriEzTk" +
					"YmxxSUn/2opOGAz8UiU/Tp663vo9jT7LsKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH46" +
					"5mrr0xnkiIZK2BznjqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60" +
					"h9Jh14Pe6+KosrjrF6xqpQ==",
				raw: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1C\r\n" +
					"         TcWLKONKZYFWz3ERlTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5m\r\n" +
					"         NlNkuZPygJf0kM9JYc6wW/m7mpriEzTkYmxxSUn/2opOGAz8UiU/Tp663vo9jT7L\r\n" +
					"         sKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH465mrr0xnkiIZK2Bzn\r\n" +
					"         jqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60\r\n" +
					"         h9Jh14Pe6+KosrjrF6xqpQ==\r\n",
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			ams, err := ParseARCMessageSignature(tc.input)
			if err != nil {
				t.Fatalf("failed to parse: %s", err)
			}
			if ams.InstanceNumber != tc.expected.InstanceNumber {
				t.Errorf("instance number mismatch: got %d, want %d", ams.InstanceNumber, tc.expected.InstanceNumber)
			}
			if ams.Algorithm != tc.expected.Algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", ams.Algorithm, tc.expected.Algorithm)
			}
			if ams.BodyHash != tc.expected.BodyHash {
				t.Errorf("body hash mismatch: got %s, want %s", ams.BodyHash, tc.expected.BodyHash)
			}
			if ams.Canonicalization != tc.expected.Canonicalization {
				t.Errorf("canonicalization mismatch: got %s, want %s", ams.Canonicalization, tc.expected.Canonicalization)
			}
			if ams.Domain != tc.expected.Domain {
				t.Errorf("domain mismatch: got %s, want %s", ams.Domain, tc.expected.Domain)
			}
			if ams.Headers != tc.expected.Headers {
				t.Errorf("headers mismatch: got %s, want %s", ams.Headers, tc.expected.Headers)
			}
			if ams.Selector != tc.expected.Selector {
				t.Errorf("selector mismatch: got %s, want %s", ams.Selector, tc.expected.Selector)
			}
			if ams.Timestamp != tc.expected.Timestamp {
				t.Errorf("timestamp mismatch: got %d, want %d", ams.Timestamp, tc.expected.Timestamp)
			}
			if ams.Signature != tc.expected.Signature {
				t.Errorf("signature mismatch: got %s, want %s", ams.Signature, tc.expected.Signature)
			}
		})
	}
}

func TestARCMessageSignatureSign(t *testing.T) {
	testCases := []struct {
		name     string
		input    *ARCMessageSignature
		headers  []string
		expected string
	}{
		{
			name: "simple/simple rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationSimple,
					Body:      CanonicalizationSimple,
					Algorithm: SignatureAlgorithmRSA_SHA256,
					HashAlgo:  crypto.SHA256,
				},
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expected: "J+LOAXHWTymcM1UpL3R+l2DHO9IgPm7SNCux/gMee3GEBoHTbXGFHrzA4Rwg99GmqOJ2TaNimsg4Hej3sEbg6/iugfl47X1Vg8uPx26bZCVC7UB62+QuLn2H/LrRpxPVznY9sF8rA0X5yQVu8OfzGl9zWgIxPlTPZ0lmlbjGbtZ5r7wJhOf7gv63dxbVupi5yboe6Y/j2/zV6NR+jaXMszJt0MWgDdpErA4omejkCNT0DPl6ET4MOGys0E5BE2FUbq0tUGke95czVntcdhZOFlD7XrDMA2GW/fVEthSrDnZhF41jnCsJtkp9ssx9XUM2Sv7S5o9Z73AHRhtAhlADGQ==",
		},
		{
			name: "relaxed/relaxed rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					Algorithm: SignatureAlgorithmRSA_SHA256,
					HashAlgo:  crypto.SHA256,
				},
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expected: "L1hEPWn4gfB3+iQOGQFUIZpmskwRVGmmTnc67/bjeuHIyIoNGjw+EKux2XYakkK/oGQXH+BUxGURzuwynG8ARfLzCxkINSriLOWkMhHn4XHt4QYQQxOF0UxkQ++TrQdSA6QE2dcfK0JjIUVK+On0EJWjoV5WohKq5xYWQsM5xOAEbgU2Hh5/olD2y1LunTuhvK23Fvtryiqq6WU7yCr/ltvY6stjRrwdMse0qP5enMgxw5quzWR5VTlI14rke05Bic3KLYSYaN/J+nWP10Feg1Wley8AyXC3u/FokcZFI0P+qSs+V9NCu7IwW3lwkH1onwXl3JiocGo5SIZ2siM3Bg==",
		},
		{
			name: "relaxed/relaxed ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject",
				Selector:         "selector",
				Timestamp:        1728300596,
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					Algorithm: SignatureAlgorithmED25519_SHA256,
					HashAlgo:  crypto.SHA256,
				},
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			expected: "R2oYJOzYoSiSWilxkEV93o6hEq/pD8kTE/ozJHeTfpFxY7A4di2iPJGEsYdYJDgHgTnLw8E5JtcnRXJlJ7j5Bw==",
		},
		{
			name: "simple/simple ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject",
				Selector:         "selector",
				Timestamp:        1728300596,
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationSimple,
					Body:      CanonicalizationSimple,
					Algorithm: SignatureAlgorithmED25519_SHA256,
					HashAlgo:  crypto.SHA256,
				},
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			expected: "9xc2b6sMqTIVulik/hQM2iAMjNhi4yuNPmNSpuipc+B8zAqz9sV0LkSgZnzZy+rjzad8Aqt1d2gXkjnIh3DUAQ==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var privateKey crypto.Signer
			if tc.input.Algorithm == SignatureAlgorithmRSA_SHA256 || tc.input.Algorithm == SignatureAlgorithmRSA_SHA1 {
				privateKey = testKeys.RSAPrivateKey
			} else if tc.input.Algorithm == SignatureAlgorithmED25519_SHA256 {
				privateKey = testKeys.ED25519PrivateKey
			}

			if err := tc.input.Sign(tc.headers, privateKey); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}
			if tc.input.Signature != tc.expected {
				t.Errorf("signature mismatch: got %s, want %s", tc.input.Signature, tc.expected)
			}
			t.Logf("Generated signature for %s: %s", tc.name, tc.input.Signature)
		})
	}
}

func TestARCMessageSignatureVerify(t *testing.T) {
	testCases := []struct {
		name      string
		bodyhash  string
		header    string
		headers   []string
		domainkey domainkey.DomainKey
	}{
		{
			name:     "simple/simple valid rsa",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=J+LOAXHWTymcM1UpL3R+l2DHO9IgPm7SNCux/gMee3GEBoHTbXGFHrzA4Rwg99GmqOJ2TaNimsg4Hej3sEbg6/iugfl47X1Vg8uPx26bZCVC7UB62+QuLn2H/LrRpxPVznY9sF8rA0X5yQVu8OfzGl9zWgIxPlTPZ0lmlbjGbtZ5r7wJhOf7gv63dxbVupi5yboe6Y/j2/zV6NR+jaXMszJt0MWgDdpErA4omejkCNT0DPl6ET4MOGys0E5BE2FUbq0tUGke95czVntcdhZOFlD7XrDMA2GW/fVEthSrDnZhF41jnCsJtkp9ssx9XUM2Sv7S5o9Z73AHRhtAhlADGQ==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=J+LOAXHWTymcM1UpL3R+l2DHO9IgPm7SNCux/gMee3GEBoHTbXGFHrzA4Rwg99GmqOJ2TaNimsg4Hej3sEbg6/iugfl47X1Vg8uPx26bZCVC7UB62+QuLn2H/LrRpxPVznY9sF8rA0X5yQVu8OfzGl9zWgIxPlTPZ0lmlbjGbtZ5r7wJhOf7gv63dxbVupi5yboe6Y/j2/zV6NR+jaXMszJt0MWgDdpErA4omejkCNT0DPl6ET4MOGys0E5BE2FUbq0tUGke95czVntcdhZOFlD7XrDMA2GW/fVEthSrDnZhF41jnCsJtkp9ssx9XUM2Sv7S5o9Z73AHRhtAhlADGQ==\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"rsa-sha256"},
				KeyType:   "rsa",
				PublicKey: testKeys.getPublicKeyBase64("rsa"),
			},
		},
		{
			name:     "relaxed/relaxed valid rsa",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=L1hEPWn4gfB3+iQOGQFUIZpmskwRVGmmTnc67/bjeuHIyIoNGjw+EKux2XYakkK/oGQXH+BUxGURzuwynG8ARfLzCxkINSriLOWkMhHn4XHt4QYQQxOF0UxkQ++TrQdSA6QE2dcfK0JjIUVK+On0EJWjoV5WohKq5xYWQsM5xOAEbgU2Hh5/olD2y1LunTuhvK23Fvtryiqq6WU7yCr/ltvY6stjRrwdMse0qP5enMgxw5quzWR5VTlI14rke05Bic3KLYSYaN/J+nWP10Feg1Wley8AyXC3u/FokcZFI0P+qSs+V9NCu7IwW3lwkH1onwXl3JiocGo5SIZ2siM3Bg==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=L1hEPWn4gfB3+iQOGQFUIZpmskwRVGmmTnc67/bjeuHIyIoNGjw+EKux2XYakkK/oGQXH+BUxGURzuwynG8ARfLzCxkINSriLOWkMhHn4XHt4QYQQxOF0UxkQ++TrQdSA6QE2dcfK0JjIUVK+On0EJWjoV5WohKq5xYWQsM5xOAEbgU2Hh5/olD2y1LunTuhvK23Fvtryiqq6WU7yCr/ltvY6stjRrwdMse0qP5enMgxw5quzWR5VTlI14rke05Bic3KLYSYaN/J+nWP10Feg1Wley8AyXC3u/FokcZFI0P+qSs+V9NCu7IwW3lwkH1onwXl3JiocGo5SIZ2siM3Bg==\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"rsa-sha256"},
				KeyType:   "rsa",
				PublicKey: testKeys.getPublicKeyBase64("rsa"),
			},
		},
		{
			name:     "relaxed/relaxed valid ed25519",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
				"        b=R2oYJOzYoSiSWilxkEV93o6hEq/pD8kTE/ozJHeTfpFxY7A4di2iPJGEsYdYJDgHgTnLw8E5JtcnRXJlJ7j5Bw==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
					"        b=R2oYJOzYoSiSWilxkEV93o6hEq/pD8kTE/ozJHeTfpFxY7A4di2iPJGEsYdYJDgHgTnLw8E5JtcnRXJlJ7j5Bw==\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"ed25519-sha256"},
				KeyType:   "ed25519",
				PublicKey: testKeys.getPublicKeyBase64("ed25519"),
			},
		},
		{
			name:     "simple/simple valid ed25519",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=ed25519-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
				"        b=9xc2b6sMqTIVulik/hQM2iAMjNhi4yuNPmNSpuipc+B8zAqz9sV0LkSgZnzZy+rjzad8Aqt1d2gXkjnIh3DUAQ==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"ARC-Message-Signature: i=1; a=ed25519-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
					"        b=9xc2b6sMqTIVulik/hQM2iAMjNhi4yuNPmNSpuipc+B8zAqz9sV0LkSgZnzZy+rjzad8Aqt1d2gXkjnIh3DUAQ==\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"ed25519-sha256"},
				KeyType:   "ed25519",
				PublicKey: testKeys.getPublicKeyBase64("ed25519"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ams, err := ParseARCMessageSignature(tc.header)
			if err != nil {
				t.Fatalf("failed to parse arc message signature: %s", err)
			}

			// For debugging: Sign the headers and compare the signature
			// This is to check if the test case signatures are correct
			debugAMS := &ARCMessageSignature{
				Algorithm:        ams.Algorithm,
				BodyHash:         ams.BodyHash,
				Canonicalization: ams.Canonicalization,
				Domain:           ams.Domain,
				Headers:          ams.Headers,
				Selector:         ams.Selector,
				InstanceNumber:   ams.InstanceNumber,
				Timestamp:        ams.Timestamp,
			}
			var privateKey crypto.Signer
			if ams.Algorithm == SignatureAlgorithmRSA_SHA256 || ams.Algorithm == SignatureAlgorithmRSA_SHA1 {
				privateKey = testKeys.RSAPrivateKey
			} else if ams.Algorithm == SignatureAlgorithmED25519_SHA256 {
				privateKey = testKeys.ED25519PrivateKey
			}
			err = debugAMS.Sign(tc.headers, privateKey)
			if err != nil {
				t.Fatalf("failed to sign for debugging: %s", err)
			}

			result := ams.Verify(tc.headers, tc.bodyhash, &tc.domainkey)

			if result.Error() != nil {
				t.Errorf("verify failed: %s", result.Error())
			}
		})
	}
}

func TestARCMessageSignatureSignAndVerify(t *testing.T) {
	headers := []string{
		"From: alice@example.com\r\n",
		"To: bob@example.com\r\n",
		"Subject: Test\r\n",
	}

	// Calculate actual body hash for the test
	body := "Hello World!\r\n" // Simple body for testing
	bodyHashCalculator := bodyhash.NewBodyHash(canonical.Relaxed, crypto.SHA256, 0)
	bodyHashCalculator.Write([]byte(body))
	bodyHashCalculator.Close()
	actualBodyHash := bodyHashCalculator.Get()

	ams := &ARCMessageSignature{
		Algorithm:        SignatureAlgorithmRSA_SHA256,
		Canonicalization: "relaxed/relaxed",
		Domain:           "example.com",
		Selector:         "default",
		InstanceNumber:   1,
		BodyHash:         actualBodyHash,
	}

	// Mock key for signing
	privateKey := testKeys.RSAPrivateKey

	// Sign
	err := ams.Sign(headers, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Mock domain key for verification
	domainKey := &domainkey.DomainKey{
		PublicKey: testKeys.RSAPublicKeyBase64,
		KeyType:   "rsa",
	}

	// Verify
	// Parse the signature header to set the raw field
	parsedAMS, err := ParseARCMessageSignature("ARC-Message-Signature: " + ams.String() + "\r\n")
	if err != nil {
		t.Fatalf("Failed to parse ARC-Message-Signature: %v", err)
	}
	// Set the signature to the one generated by Sign function for verification
	//parsedAMS.Signature = "UEbs7onwJ0OmfT0M3EWURRximbYTQfwWn0B8vE80U9oQX74KmpG2tExJtwZ/qoO+hBPTCryAL3FVqdh/tufXHjLetRdfr5IQ60R5Eh4ea2mrFnOF4dUVXD6nLxzPFl8IwYD+AWTlEz9uz5w7NiyqoLJ5RYiMlPszMYOPyZrbqD/a3HVMHxGS41vL++Tk1RSstp3WSm+P665EQUFRTmfwHxLfyDMX3D6K/PvWKXFHbXuq4tVjsNpTY5ApIfs1bTyLddLjim0g+Xtf1F0Br4IyexnptgiVUJ0B+kvH9nMRF+ORsEJRdF5yTimZ3aU+vjcUNUyEt1JYMWhYo5pDBCaThg=="
	if err != nil {
		t.Fatalf("Failed to parse ARC-Message-Signature: %v", err)
	}
	// Note: We need to pass the headers including the signature header for verification
	allHeaders := append(headers, "ARC-Message-Signature: "+ams.String()+"\r\n")
	result := parsedAMS.Verify(allHeaders, actualBodyHash, domainKey)
	if result.Error() != nil {
		t.Errorf("Verification failed: %s - %s", result.Status(), result.Message())
	}
}
