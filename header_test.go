package mmauth

import (
	"bufio"
	"crypto"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func Test_readHeader(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expect        headers
		expectedError bool
	}{
		{
			name:          "empty input",
			expectedError: true,
		},
		{
			name:   "empty",
			input:  "\r\n\r\n",
			expect: headers{},
		},
		{
			name: "normal",
			input: "header:hoge\r\n" +
				"Header2:fuga\r\n" +
				"Header3:pi\r\n\tyo\r\n\r\n",
			expect: headers{
				"header:hoge\r\n",
				"Header2:fuga\r\n",
				"Header3:pi\r\n\tyo\r\n",
			},
		},
		{
			name:  "one header",
			input: "header:hoge\r\n\r\nbody\r\n",
			expect: headers{
				"header:hoge\r\n",
			},
		},
		{
			name:  "non body",
			input: "header:hoge\r\n\r\n",
			expect: headers{
				"header:hoge\r\n",
			},
		},
		{
			name:   "header only",
			input:  "From: a@example.com\r\n",
			expect: headers{"From: a@example.com\r\n"},
		},
		{
			name:  "header only with folding",
			input: "From: a@example.com\r\nSubject: hello\r\n\tworld\r\n",
			expect: headers{
				"From: a@example.com\r\n",
				"Subject: hello\r\n\tworld\r\n",
			},
		},
		{
			name:  "header only LF",
			input: "From: a@example.com\nSubject: hello\n",
			expect: headers{
				"From: a@example.com\r\n",
				"Subject: hello\r\n",
			},
		},
		{
			name:   "header only field name boundaries",
			input:  "!: first\r\n~: last\r\n",
			expect: headers{"!: first\r\n", "~: last\r\n"},
		},
		{
			name:   "header only obsolete whitespace before colon",
			input:  "From \t: a@example.com\r\n",
			expect: headers{"From \t: a@example.com\r\n"},
		},
		{
			name:          "header only missing colon",
			input:         "not-a-header\r\n",
			expectedError: true,
		},
		{
			name:          "header only malformed last line",
			input:         "From: a@example.com\r\nnot-a-header\r\n",
			expectedError: true,
		},
		{
			name:          "header only colon in continuation",
			input:         "not-a-header\r\n\tcontinued: value\r\n",
			expectedError: true,
		},
		{
			name:          "header only empty field name",
			input:         ": value\r\n",
			expectedError: true,
		},
		{
			name:          "header only whitespace in field name",
			input:         "Bad Name: value\r\n",
			expectedError: true,
		},
		{
			name:          "header only control in field name",
			input:         "Bad\x00Name: value\r\n",
			expectedError: true,
		},
		{
			name:          "header only DEL in field name",
			input:         "Bad\x7fName: value\r\n",
			expectedError: true,
		},
		{
			name:          "header only non-ASCII field name",
			input:         "X-é: value\r\n",
			expectedError: true,
		},
		{
			name:          "header only orphan continuation",
			input:         "\torphan: value\r\n",
			expectedError: true,
		},
		{
			name:          "unterminated last header",
			input:         "From: a@example.com\r\nSubject: hello",
			expectedError: true,
		},
		{
			name:          "unterminated continuation",
			input:         "Subject: hello\r\n\tworld",
			expectedError: true,
		},
		{
			name:          "non header crlf",
			input:         "header:hoge",
			expectedError: true,
		},
		{
			name:          "non body crlf",
			input:         "header:hoge\r\nbody",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.input)
			br := bufio.NewReader(r)
			got, err := readHeader(br)
			if err == nil && tc.expectedError {
				t.Errorf("expected error, but no error")
				return
			} else if tc.expectedError {
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != len(tc.expect) {
				t.Errorf("unexpected result: got=%d, expect=%d", len(got), len(tc.expect))
			}
			for i, v := range got {
				if v != tc.expect[i] {
					t.Errorf("unexpected result: got=%s, expect=%s", v, tc.expect[i])
				}
			}
		})
	}
}

func TestReadHeaderReadError(t *testing.T) {
	sentinel := errors.New("header read failed")
	r := io.MultiReader(strings.NewReader("From: a@example.com\r\n"), iotest.ErrReader(sentinel))
	if _, err := readHeader(bufio.NewReader(r)); err == nil || !strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestReadHeaderFieldNameValidationAtBothEndings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"missing colon", "NoColon\r\n"},
		{"empty name", ": value\r\n"},
		{"space in name", "Bad Name: value\r\n"},
		{"control in name", "Bad\x00Name: value\r\n"},
		{"non ASCII name", "X-é: value\r\n"},
		{"orphan continuation", "\torphan: value\r\n"},
	} {
		for _, ending := range []struct {
			name string
			text string
		}{
			{"EOF", ""},
			{"separator", "\r\nbody\r\n"},
		} {
			t.Run(tc.name+"/"+ending.name, func(t *testing.T) {
				prefix := "Date: Mon, 12 Oct 2026 00:00:00 +0000\r\n"
				if tc.name == "orphan continuation" {
					prefix = ""
				}
				input := prefix + tc.field + ending.text
				_, err := readHeader(bufio.NewReader(strings.NewReader(input)))
				if err == nil || !strings.Contains(err.Error(), "invalid header field") {
					t.Fatalf("malformed field accepted: %v", err)
				}
			})
		}
	}
}

func TestReadHeaderLongValidLines(t *testing.T) {
	for _, length := range []int{78, 998} {
		field := "X: " + strings.Repeat("a", length-3) + "\r\n"
		for _, ending := range []string{"", "\r\nbody\r\n"} {
			reader := bufio.NewReader(strings.NewReader(field + ending))
			got, err := readHeader(reader)
			if err != nil || len(got) != 1 || got[0] != field {
				t.Fatalf("length=%d ending=%q: fields=%q err=%v", length, ending, got, err)
			}
			if ending != "" {
				body, err := io.ReadAll(reader)
				if err != nil || string(body) != "body\r\n" {
					t.Fatalf("body changed: %q, %v", body, err)
				}
			}
		}
	}
}

func TestMMAuthCloseReturnsParseError(t *testing.T) {
	for _, input := range []string{"header:value", "not-a-header\r\n", "From: a@example.com\r\nnot-a-header\r\n", "From: a@example.com\r\nBad Name: value\r\n\r\nbody\r\n"} {
		t.Run(input, func(t *testing.T) {
			m := NewMMAuth()
			if _, err := m.Write([]byte(input)); err != nil {
				t.Fatalf("unexpected write error: %v", err)
			}
			if err := m.Close(); err == nil || !strings.Contains(err.Error(), "failed to read header") {
				t.Fatalf("expected parse error from Close, got %v", err)
			}
		})
	}
}

func Test_hashAlgo(t *testing.T) {
	testCases := []struct {
		name   string
		input  SignatureAlgorithm
		expect crypto.Hash
	}{
		{
			name:   "rsa-sha1",
			input:  SignatureAlgorithmRSA_SHA1,
			expect: crypto.SHA1,
		},
		{
			name:   "rsa-sha256",
			input:  SignatureAlgorithmRSA_SHA256,
			expect: crypto.SHA256,
		},
		{
			name:   "ed25519-sha256",
			input:  SignatureAlgorithmED25519_SHA256,
			expect: crypto.SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hashAlgo(tc.input)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%s, expect=%s", got, tc.expect)
			}
		})
	}
}

func Test_isCcanonicalizationBodyAndAlgorithm(t *testing.T) {
	testCases := []struct {
		name   string
		input  BodyCanonicalizationAndAlgorithm
		can    []BodyCanonicalizationAndAlgorithm
		expect bool
	}{
		{
			name: "true",
			input: BodyCanonicalizationAndAlgorithm{
				Body:      CanonicalizationSimple,
				Algorithm: crypto.SHA1,
			},
			can: []BodyCanonicalizationAndAlgorithm{
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA256,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA256,
				},
			},
			expect: true,
		},
		{
			name: "false",
			input: BodyCanonicalizationAndAlgorithm{
				Body:      CanonicalizationSimple,
				Algorithm: crypto.SHA1,
			},
			can: []BodyCanonicalizationAndAlgorithm{
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA256,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA256,
				},
			},
			expect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isCcanonicalizationBodyAndAlgorithm(tc.input, tc.can)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%t, expect=%t", got, tc.expect)
			}
		})
	}
}

func Test_parseHeaderCanonicalization(t *testing.T) {
	testCase := []struct {
		name         string
		input        string
		expectHeader Canonicalization
		expectBody   Canonicalization
	}{
		{
			name:         "simple/simple",
			input:        "simple/simple",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "relaxed/relaxed",
			input:        "relaxed/relaxed",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationRelaxed,
		},
		{
			name:         "simple/relaxed",
			input:        "simple/relaxed",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationRelaxed,
		},
		{
			name:         "relaxed/simple",
			input:        "relaxed/simple",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "simple",
			input:        "simple",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "relaxed",
			input:        "relaxed",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "none",
			input:        "",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
	}
	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			header, body, err := parseHeaderCanonicalization(tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if header != tc.expectHeader {
				t.Errorf("unexpected result: got=%s, expect=%s", header, tc.expectHeader)
			}
			if body != tc.expectBody {
				t.Errorf("unexpected result: got=%s, expect=%s", body, tc.expectBody)
			}
		})
	}
}
