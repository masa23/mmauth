package dkim2

import (
	"bytes"
	"strings"
	"testing"
)

// X- fields are ignored by DKIM2 hashes, so padding does not invalidate the
// authenticated input used to exercise Forward and Revise output limits.
func outputLimitHeaderPadding(size int) []byte {
	var out bytes.Buffer
	for size > 0 {
		fieldSize := size
		if fieldSize > maxHeaderFieldBytes {
			fieldSize = maxHeaderFieldBytes
		}
		if remainder := size - fieldSize; remainder > 0 && remainder < 5 {
			fieldSize -= 5
		}
		out.WriteString("X-:")
		out.WriteString(strings.Repeat("a", fieldSize-5))
		out.WriteString("\r\n")
		size -= fieldSize
	}
	return out.Bytes()
}

func TestSigningOperationsEnforceOutputHeaderLimits(t *testing.T) {
	key := edKey()
	initialOptions := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.test>"},
	}, Timestamp: testTime}
	first, err := Sign(original(), initialOptions)
	if err != nil {
		t.Fatal(err)
	}
	nextOptions := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: Envelope{
		MailFrom: "<bounce@relay.test>", RcptTo: []string{"<carol@destination.test>"},
	}, Timestamp: testTime, OutOfBandArrangement: true}
	for _, test := range []struct {
		name  string
		input []byte
		add   int
		sign  func([]byte) ([]byte, error)
	}{
		{"Sign", original(), 2, func(wire []byte) ([]byte, error) { return Sign(wire, initialOptions) }},
		{"Forward", first, 1, func(wire []byte) ([]byte, error) { return Forward(wire, nextOptions) }},
		{"Revise", append(append([]byte(nil), first...), []byte("footer\r\n")...), 2, func(wire []byte) ([]byte, error) {
			return Revise(wire, []byte(`{"b":[{"c":[1,1]}]}`), nextOptions)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(test.input)
			if err != nil {
				t.Fatal(err)
			}
			for _, extra := range []int{0, 1} {
				count := maxHeaderFields - test.add - len(parsed.Headers) + extra
				wire := append([]byte(strings.Repeat("X-:\r\n", count)), test.input...)
				if _, err := Parse(wire); err != nil {
					t.Fatalf("boundary test input invalid: %v", err)
				}
				out, err := test.sign(wire)
				if extra == 0 {
					if err != nil {
						t.Fatal(err)
					}
					result, err := Parse(out)
					if err != nil || len(result.Headers) != maxHeaderFields {
						t.Fatalf("boundary output invalid: %v", err)
					}
				} else if err == nil || out != nil || !strings.Contains(err.Error(), "header count exceeds") {
					t.Fatalf("oversized output accepted: len=%d err=%v", len(out), err)
				}
			}
			baseline, err := test.sign(test.input)
			if err != nil {
				t.Fatal(err)
			}
			overhead := len(baseline) - len(test.input)
			inputHeaders := bytes.Index(test.input, []byte("\r\n\r\n")) + 2
			for _, extra := range []int{0, 1} {
				wire := append(outputLimitHeaderPadding(maxHeaderBytes-inputHeaders-overhead+extra), test.input...)
				if _, err := Parse(wire); err != nil {
					t.Fatalf("header size test input invalid: %v", err)
				}
				out, err := test.sign(wire)
				if extra == 0 {
					if err != nil {
						t.Fatal(err)
					}
					if got := bytes.Index(out, []byte("\r\n\r\n")) + 2; got != maxHeaderBytes {
						t.Fatalf("headers=%d, want %d", got, maxHeaderBytes)
					}
				} else if err == nil || out != nil || !strings.Contains(err.Error(), "headers exceed") {
					t.Fatalf("oversized header output accepted: len=%d err=%v", len(out), err)
				}
			}
		})
	}
}

func TestSignEnforcesOutputMessageLimit(t *testing.T) {
	options := SignOptions{Domain: "example.com", Selector: "s1", Key: edKey(), Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.test>"},
	}, Timestamp: testTime}
	base := []byte("From: alice@example.com\r\n\r\n")
	baseline, err := Sign(base, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []int{0, 1} {
		wire := append(append([]byte(nil), base...), bytes.Repeat([]byte("a"), maxMessageBytes-len(baseline)+extra)...)
		out, err := Sign(wire, options)
		if extra == 0 {
			if err != nil || len(out) != maxMessageBytes {
				t.Fatalf("boundary output: len=%d err=%v", len(out), err)
			}
		} else if err == nil || out != nil || !strings.Contains(err.Error(), "message exceeds") {
			t.Fatalf("oversized message output accepted: len=%d err=%v", len(out), err)
		}
	}
}

func TestSigningRejectsOversizedGeneratedFields(t *testing.T) {
	key := edKey()
	initialOptions := SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: Envelope{
		MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.test>"},
	}, Timestamp: testTime}
	first, err := Sign(original(), initialOptions)
	if err != nil {
		t.Fatal(err)
	}
	nextOptions := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: Envelope{
		MailFrom: "<bounce@relay.test>", RcptTo: []string{"<carol@destination.test>"},
	}, Timestamp: testTime, OutOfBandArrangement: true}
	initialOptions.Envelope.RcptTo = make([]string, 2000)
	for i := range initialOptions.Envelope.RcptTo {
		initialOptions.Envelope.RcptTo[i] = "<recipient@destination.test>"
	}
	if out, err := Sign(original(), initialOptions); err == nil || out != nil || !strings.Contains(err.Error(), "header field exceeds") {
		t.Fatalf("oversized generated signature accepted: %v", err)
	}
	nextOptions.Envelope.RcptTo = initialOptions.Envelope.RcptTo
	if out, err := Forward(first, nextOptions); err == nil || out != nil || !strings.Contains(err.Error(), "header field exceeds") {
		t.Fatalf("oversized forwarded signature accepted: %v", err)
	}
	nextOptions.Envelope.RcptTo = []string{"<carol@destination.test>"}
	modified := append(append([]byte(nil), first...), []byte("footer\r\n")...)
	recipe := []byte(`{"b":[{"c":[1,1]}]}` + strings.Repeat(" ", maxHeaderFieldBytes))
	if out, err := Revise(modified, recipe, nextOptions); err == nil || out != nil || !strings.Contains(err.Error(), "header field exceeds") {
		t.Fatalf("oversized generated Recipe accepted: %v", err)
	}
}
