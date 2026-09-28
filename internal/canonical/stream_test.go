package canonical

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"
)

// A line-oriented reference, deliberately independent of the streaming state.
func referenceBody(input []byte, mode Canonicalization) string {
	lines := strings.Split(strings.ReplaceAll(string(input), "\r\n", "\n"), "\n")
	if mode == Relaxed {
		for i, line := range lines {
			var out strings.Builder
			space := false
			for _, ch := range []byte(line) {
				if ch == ' ' || ch == '\t' {
					space = true
					continue
				}
				if space {
					out.WriteByte(' ')
					space = false
				}
				out.WriteByte(ch)
			}
			lines[i] = out.String()
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 && mode == Relaxed {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func checkBodyChunks(t *testing.T, input []byte, chunk int) {
	t.Helper()
	for _, mode := range []Canonicalization{Simple, Relaxed} {
		var got bytes.Buffer
		w := Body(&got, mode)
		for off := 0; off < len(input); off += chunk {
			end := off + chunk
			if end > len(input) {
				end = len(input)
			}
			if n, err := w.Write(input[off:end]); err != nil || n != end-off {
				t.Fatalf("Write = %d, %v", n, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		want := referenceBody(input, mode)
		if got.String() != want {
			t.Fatalf("%s chunk=%d input=%q: got=%q want=%q", mode, chunk, input, got.String(), want)
		}
	}
}

func TestBodyChunkBoundaries(t *testing.T) {
	for _, input := range []string{"", "\r\n", " \t", "\r", "\r\r\n", " \r\n\r\na\t b \t\r\n \t\r\n", "a\r\nb\n\tc\r"} {
		for chunk := 1; chunk <= len(input)+1; chunk++ {
			checkBodyChunks(t, []byte(input), chunk)
		}
	}
	r := rand.New(rand.NewSource(42))
	alphabet := []byte{'a', 'b', ' ', '\t', '\r', '\n', 0, 255}
	for i := 0; i < 1000; i++ {
		input := make([]byte, r.Intn(512))
		for j := range input {
			input[j] = alphabet[r.Intn(len(alphabet))]
		}
		checkBodyChunks(t, input, 1+r.Intn(32))
	}
}

type byteCounter int

func (c *byteCounter) Write(p []byte) (int, error) { *c += byteCounter(len(p)); return len(p), nil }

func TestBodyStreamsBeforeClose(t *testing.T) {
	for _, mode := range []Canonicalization{Simple, Relaxed} {
		var written byteCounter
		w := Body(&written, mode)
		block := []byte(strings.Repeat("x", 64<<10))
		for i := 0; i < 32; i++ {
			if _, err := w.Write(block); err != nil {
				t.Fatal(err)
			}
			if int(written) < (i+1)*len(block)-4096 {
				t.Fatal("body buffered instead of streamed")
			}
		}
		// Long deferred whitespace and trailing empty lines require constant state.
		for _, block := range []string{strings.Repeat(" \t", 32<<10), strings.Repeat("\r\n", 32<<10)} {
			if _, err := io.WriteString(w, block); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write(p []byte) (int, error) { return 0, w.err }
func TestBodyWriterErrors(t *testing.T) {
	sentinel := errors.New("write failure")
	for _, mode := range []Canonicalization{Simple, Relaxed} {
		for _, size := range []int{1, 8192} {
			w := Body(failingWriter{sentinel}, mode)
			_, err := w.Write(bytes.Repeat([]byte("x"), size))
			if size > 4096 && !errors.Is(err, sentinel) {
				t.Fatalf("Write error = %v", err)
			}
			if err := w.Close(); !errors.Is(err, sentinel) {
				t.Fatalf("Close error = %v", err)
			}
			if err := w.Close(); !errors.Is(err, sentinel) {
				t.Fatalf("second Close error = %v", err)
			}
		}
	}
}

func FuzzBodyChunks(f *testing.F) {
	for _, s := range []string{"", "a\r\n\r\n", " \t\r\n b\t c ", "\r\r\n\x00"} {
		f.Add([]byte(s), uint8(1))
	}
	f.Fuzz(func(t *testing.T, input []byte, chunk uint8) {
		if len(input) > 65536 {
			t.Skip()
		}
		checkBodyChunks(t, input, int(chunk)+1)
	})
}
