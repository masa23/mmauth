package dkim2

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestRecipeBodyCopyBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, body string
		steps      []recipeStep
		want       string
		bad        bool
	}{
		{"empty body", "", []recipeStep{{Copy: []int{1, 1}}}, "", true},
		{"one empty line", "\r\n", []recipeStep{{Copy: []int{1, 1}}}, "\r\n", false},
		{"no phantom line", "one\r\n", []recipeStep{{Copy: []int{2, 2}}}, "", true},
		{"trailing empty line", "one\r\n\r\n", []recipeStep{{Copy: []int{2, 2}}}, "\r\n", false},
		{"unterminated line", "one", []recipeStep{{Copy: []int{1, 1}}}, "one\r\n", false},
		{"unterminated last", "one\r\ntwo", []recipeStep{{Copy: []int{2, 2}}}, "two\r\n", false},
		{"whole unterminated body", "one\r\ntwo", []recipeStep{{Copy: []int{1, 2}}}, "one\r\ntwo\r\n", false},
		{"past unterminated last", "one\r\ntwo", []recipeStep{{Copy: []int{1, 3}}}, "", true},
		{"gap and data", "one\r\ntwo\r\nthree\r\nfour\r\n", []recipeStep{{Copy: []int{1, 1}}, {Data: []string{"inserted"}}, {Copy: []int{3, 4}}}, "one\r\ninserted\r\nthree\r\nfour\r\n", false},
		{"adjacent ranges", "one\r\ntwo\r\n", []recipeStep{{Copy: []int{1, 1}}, {Copy: []int{2, 2}}}, "one\r\ntwo\r\n", false},
		{"binary body", "\xff\r\n\x00\xfe", []recipeStep{{Copy: []int{2, 2}}}, "\x00\xfe\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &Message{Headers: []string{"From: a@example.com\r\n"}, Body: []byte(test.body)}
			got, err := applyRecipe(input, recipe{HasBody: true, Body: test.steps})
			if test.bad {
				if err == nil {
					t.Fatal("out-of-range body copy accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Body) != test.want {
				t.Fatalf("body=%q, want %q", got.Body, test.want)
			}
			if string(input.Body) != test.body {
				t.Fatal("Recipe changed its input")
			}
		})
	}
}

// A CRLF-dense bounded message must not allocate an index entry per line or
// copy its old body when reconstructing a small (or empty) previous body.
func TestRecipeBodyMemoryBound(t *testing.T) {
	body := bytes.Repeat([]byte("\r\n"), maxMessageBytes/2)
	lineCount := len(body) / 2
	for _, test := range []struct {
		name  string
		steps []recipeStep
		want  string
	}{
		{"first line", []recipeStep{{Copy: []int{1, 1}}}, "\r\n"},
		{"last line", []recipeStep{{Copy: []int{lineCount, lineCount}}}, "\r\n"},
		{"sparse ranges", []recipeStep{{Copy: []int{1, 1}}, {Copy: []int{lineCount, lineCount}}}, "\r\n\r\n"},
		{"data only", []recipeStep{{Data: []string{"new"}}}, "new\r\n"},
		{"empty recipe", nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &Message{Body: body}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			got, err := applyRecipe(input, recipe{HasBody: true, Body: test.steps})
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Body) != test.want {
				t.Fatalf("body=%q, want %q", got.Body, test.want)
			}
			// Allow ample runtime overhead while rejecting either the old
			// 32 MiB body clone or the roughly 256 MiB line index.
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
				t.Fatalf("allocated %d bytes to reconstruct %d bytes", allocated, len(got.Body))
			}
		})
	}
}

func TestRecipeWithoutBodyKeepsIndependentBody(t *testing.T) {
	input := &Message{Body: []byte("unchanged\r\n")}
	got, err := applyRecipe(input, recipe{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, input.Body) {
		t.Fatal("body was not retained")
	}
	got.Body[0] = 'X'
	if string(input.Body) != "unchanged\r\n" {
		t.Fatal("reconstructed body aliases its input")
	}
}

func TestRecipeBodyOutputLimit(t *testing.T) {
	// Copying this unterminated line adds CRLF and exactly fills the limit.
	body := bytes.Repeat([]byte("x"), (64<<20)-2)
	for _, test := range []struct {
		name  string
		steps []recipeStep
		bad   bool
	}{
		{"at limit", []recipeStep{{Copy: []int{1, 1}}}, false},
		{"data exceeds limit", []recipeStep{{Copy: []int{1, 1}}, {Data: []string{""}}}, true},
		{"copy exceeds limit", []recipeStep{{Data: []string{""}}, {Copy: []int{1, 1}}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := applyRecipe(&Message{Body: body}, recipe{HasBody: true, Body: test.steps})
			if test.bad {
				if err == nil || !strings.Contains(err.Error(), "reconstructed body exceeds 64 MiB") {
					t.Fatalf("output limit error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Body) != 64<<20 || !bytes.HasSuffix(got.Body, []byte("\r\n")) {
				t.Fatal("body at the output limit was not reconstructed")
			}
		})
	}
}

func TestRecipeDenseBodySigningAndVerification(t *testing.T) {
	key := edKey()
	incoming := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	outgoing := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
	verification := VerifyOptions{Resolver: records{
		"s1._domainkey.example.com": {keyRecord(key)},
		"s2._domainkey.relay.test":  {keyRecord(key)},
	}, Now: testTime}
	first, err := Sign([]byte("From: alice@example.com\r\n\r\n\r\n"), SignOptions{
		Domain: "example.com", Selector: "s1", Key: key, Envelope: incoming, Timestamp: testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	end := bytes.Index(first, []byte("\r\n\r\n")) + 4
	modified := append(append([]byte(nil), first[:end]...), bytes.Repeat([]byte("\r\n"), 1<<20)...)
	revised, err := ReviseChecked(first, modified, incoming, verification, []byte(`{"b":[{"c":[1,1]}]}`), SignOptions{
		Domain: "relay.test", Selector: "s2", Key: key, Envelope: outgoing, Timestamp: testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := Verify(revised, outgoing, verification); got.Status != Pass {
		t.Fatalf("dense body Recipe verification: %+v", got)
	}
}

// Compare the bounded scanner with a simple line-array model for arbitrary
// bytes, missing final CRLFs, gaps, and out-of-bounds ranges.
func FuzzRecipeBodyCopy(f *testing.F) {
	f.Add([]byte(""), uint8(0), uint8(0), uint8(0), uint8(0))
	f.Add([]byte("\r\n"), uint8(0), uint8(0), uint8(0), uint8(0))
	f.Add([]byte("one\r\ntwo\r\nthree\r\nfour"), uint8(0), uint8(0), uint8(1), uint8(0))
	f.Add([]byte("\xff\r\n\r\n\x00\xfe\r\n"), uint8(0), uint8(1), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, body []byte, a, b, c, d uint8) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		first, last := int(a)+1, int(a)+int(b)+1
		nextFirst, nextLast := last+int(c)+1, last+int(c)+int(d)+1
		steps := []recipeStep{{Copy: []int{first, last}}, {Data: []string{"inserted"}}, {Copy: []int{nextFirst, nextLast}}}
		var lines []string
		if len(body) > 0 {
			lines = strings.Split(string(body), "\r\n")
			if lines[len(lines)-1] == "" {
				lines = lines[:len(lines)-1]
			}
		}
		got, err := applyRecipe(&Message{Body: body}, recipe{HasBody: true, Body: steps})
		if nextLast > len(lines) {
			if err == nil {
				t.Fatal("out-of-range body copy accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Join(lines[first-1:last], "\r\n") + "\r\ninserted\r\n" + strings.Join(lines[nextFirst-1:nextLast], "\r\n") + "\r\n"
		if string(got.Body) != want {
			t.Fatalf("body=%q, want %q", got.Body, want)
		}
	})
}
