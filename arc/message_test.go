package arc

import (
	"crypto"
	"strings"
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
		name    string
		input   *ARCMessageSignature
		headers []string
	}{
		{
			name: "simple/simple rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
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
		},
		{
			name: "relaxed/relaxed rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
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
		},
		{
			name: "relaxed/relaxed ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
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
		},
		{
			name: "simple/simple ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set Headers field based on the headers in the test case
			var headerNames []string
			for _, header := range tc.headers {
				k, _, ok := strings.Cut(header, ":")
				if !ok {
					continue
				}
				headerNames = append(headerNames, strings.TrimSpace(k))
			}
			tc.input.Headers = strings.Join(headerNames, ":")

			var privateKey crypto.Signer
			if tc.input.Algorithm == SignatureAlgorithmRSA_SHA256 || tc.input.Algorithm == SignatureAlgorithmRSA_SHA1 {
				privateKey = testKeys.RSAPrivateKey
			} else if tc.input.Algorithm == SignatureAlgorithmED25519_SHA256 {
				privateKey = testKeys.ED25519PrivateKey
			}

			if err := tc.input.Sign(tc.headers, privateKey); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			// Verify the generated signature
			amsHeader := "ARC-Message-Signature: " + tc.input.String() + "\r\n"
			parsedAMS, err := ParseARCMessageSignature(amsHeader)
			if err != nil {
				t.Fatalf("failed to parse generated signature: %s", err)
			}

			headersWithAMS := append(tc.headers, amsHeader)
			result := parsedAMS.Verify(headersWithAMS, tc.input.BodyHash, &domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{getHashAlgoType(tc.input.Algorithm)},
				KeyType:   domainkey.KeyType(getKeyType(tc.input.Algorithm)),
				PublicKey: getPublicKeyBase64(tc.input.Algorithm),
			})

			if result.Error() != nil {
				t.Errorf("verification of generated signature failed: %s", result.Error())
			}

			// Commented out to remove extra debug messages
			// t.Logf("Generated signature for %s: %s", tc.name, tc.input.Signature)
		})
	}
}

// Helper function to get key type from algorithm
func getKeyType(algo SignatureAlgorithm) string {
	switch algo {
	case SignatureAlgorithmRSA_SHA1, SignatureAlgorithmRSA_SHA256:
		return "rsa"
	case SignatureAlgorithmED25519_SHA256:
		return "ed25519"
	default:
		return "rsa"
	}
}

// Helper function to get public key base64 from algorithm
func getPublicKeyBase64(algo SignatureAlgorithm) string {
	switch algo {
	case SignatureAlgorithmRSA_SHA1, SignatureAlgorithmRSA_SHA256:
		return testKeys.getPublicKeyBase64("rsa")
	case SignatureAlgorithmED25519_SHA256:
		return testKeys.getPublicKeyBase64("ed25519")
	default:
		return testKeys.getPublicKeyBase64("rsa")
	}
}

func TestARCMessageSignatureVerify(t *testing.T) {
	testCases := []struct {
		name      string
		bodyhash  string
		headers   []string
		domainkey domainkey.DomainKey
	}{
		{
			name:     "simple/simple valid rsa",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{domainkey.HashAlgoSHA256},
				KeyType:   domainkey.KeyType("rsa"),
				PublicKey: testKeys.getPublicKeyBase64("rsa"),
			},
		},
		{
			name:     "relaxed/relaxed valid rsa",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{domainkey.HashAlgoSHA256},
				KeyType:   domainkey.KeyType("rsa"),
				PublicKey: testKeys.getPublicKeyBase64("rsa"),
			},
		},
		{
			name:     "relaxed/relaxed valid ed25519",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{domainkey.HashAlgoSHA256},
				KeyType:   domainkey.KeyType("ed25519"),
				PublicKey: testKeys.getPublicKeyBase64("ed25519"),
			},
		},
		{
			name:     "simple/simple valid ed25519",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{domainkey.HashAlgoSHA256},
				KeyType:   domainkey.KeyType("ed25519"),
				PublicKey: testKeys.getPublicKeyBase64("ed25519"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create ARCMessageSignature for signing
			ams := &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        getSignatureAlgorithmFromName(tc.name),
				BodyHash:         tc.bodyhash,
				Canonicalization: getCanonicalizationFromName(tc.name),
				Domain:           "example.com",
				Selector:         "selector",
				Timestamp:        getTimestampFromName(tc.name),
				canonnAndAlgo: &CanonicalizationAndAlgorithm{
					Header:    getHeaderCanonicalization(getCanonicalizationFromName(tc.name)),
					Body:      getBodyCanonicalization(getCanonicalizationFromName(tc.name)),
					Algorithm: getSignatureAlgorithmFromName(tc.name),
					HashAlgo:  getHashAlgo(getSignatureAlgorithmFromName(tc.name)),
				},
			}

			// Set Headers field based on the headers in the test case
			headerNames := make([]string, 0, len(tc.headers))
			for _, header := range tc.headers {
				k, _, ok := strings.Cut(header, ":")
				if !ok {
					continue
				}
				headerNames = append(headerNames, strings.TrimSpace(k))
			}
			ams.Headers = strings.Join(headerNames, ":")

			// Select appropriate private key
			var privateKey crypto.Signer
			if ams.Algorithm == SignatureAlgorithmRSA_SHA256 || ams.Algorithm == SignatureAlgorithmRSA_SHA1 {
				privateKey = testKeys.RSAPrivateKey
			} else if ams.Algorithm == SignatureAlgorithmED25519_SHA256 {
				privateKey = testKeys.ED25519PrivateKey
			} else {
				// Default to RSA private key if algorithm is not set
				privateKey = testKeys.RSAPrivateKey
			}

			// Sign the headers
			err := ams.Sign(tc.headers, privateKey)
			if err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			// Create headers with AMS for verification
			headersWithAMS := append(tc.headers, "ARC-Message-Signature: "+ams.String()+"\r\n")

			// Parse the signed AMS for verification
			parsedAMS, err := ParseARCMessageSignature("ARC-Message-Signature: " + ams.String() + "\r\n")
			if err != nil {
				t.Fatalf("failed to parse arc message signature: %s", err)
			}

			// Verify the signature
			result := parsedAMS.Verify(headersWithAMS, tc.bodyhash, &tc.domainkey)

			if result.Error() != nil {
				t.Errorf("verify failed: %s", result.Error())
			}
		})
	}
}

// Helper functions to determine canonicalization and timestamp from test name
func getCanonicalizationFromName(name string) string {
	if strings.Contains(name, "simple/simple") {
		return "simple/simple"
	} else if strings.Contains(name, "relaxed/relaxed") {
		return "relaxed/relaxed"
	}
	return "simple/simple" // default
}

func getTimestampFromName(name string) int64 {
	if strings.Contains(name, "ed25519") {
		return 1728300596
	}
	return 1706971004
}

func getHeaderCanonicalization(canon string) Canonicalization {
	parts := strings.Split(canon, "/")
	if len(parts) > 0 {
		return Canonicalization(parts[0])
	}
	return CanonicalizationSimple
}

func getBodyCanonicalization(canon string) Canonicalization {
	parts := strings.Split(canon, "/")
	if len(parts) > 1 {
		return Canonicalization(parts[1])
	}
	return CanonicalizationSimple
}

func getHashAlgo(algo SignatureAlgorithm) crypto.Hash {
	switch algo {
	case SignatureAlgorithmRSA_SHA1:
		return crypto.SHA1
	case SignatureAlgorithmRSA_SHA256:
		return crypto.SHA256
	case SignatureAlgorithmED25519_SHA256:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}

// Helper function to get hash algorithm type from signature algorithm
func getHashAlgoType(algo SignatureAlgorithm) domainkey.HashAlgo {
	switch algo {
	case SignatureAlgorithmRSA_SHA1:
		return domainkey.HashAlgoSHA1
	case SignatureAlgorithmRSA_SHA256, SignatureAlgorithmED25519_SHA256:
		return domainkey.HashAlgoSHA256
	default:
		return domainkey.HashAlgoSHA256
	}
}

// Helper function to get signature algorithm from test name
func getSignatureAlgorithmFromName(name string) SignatureAlgorithm {
	if strings.Contains(name, "ed25519") {
		return SignatureAlgorithmED25519_SHA256
	}
	return SignatureAlgorithmRSA_SHA256
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
		KeyType:   domainkey.KeyType("rsa"),
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
