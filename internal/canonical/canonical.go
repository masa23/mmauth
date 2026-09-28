package canonical

import (
	"bufio"
	"io"
	"strings"
)

const crlf = "\r\n"

// シンプルとリラックスの 2 つの正規化アルゴリズムを定義します。
type Canonicalization string

const (
	Simple  Canonicalization = "simple"
	Relaxed Canonicalization = "relaxed"
)

// ヘッダのシンプル正規化を行う関数です。
func SimpleHeader(s string) string {
	return s
}

// unfoldHeader はヘッダ値の折り返しを解除する関数です。
// RFC 5322 によると、ヘッダの折り返しは CRLF とそれに続く空白文字 (WSP) でのみ構成されます。
func unfoldHeader(s string) string {
	// CRLF+WSP のシーケンスを削除（unfold）
	for {
		original := s
		s = strings.ReplaceAll(s, "\r\n ", " ")
		s = strings.ReplaceAll(s, "\r\n\t", " ")
		// 変更がなければループを抜ける
		if s == original {
			break
		}
	}
	return s
}

// ヘッダのリラックス正規化を行う関数です。
func RelaxedHeader(s string) string {
	k, v, ok := strings.Cut(s, ":")
	if !ok {
		return strings.TrimSpace(strings.ToLower(s)) + ":" + crlf
	}

	k = strings.TrimSpace(strings.ToLower(k))
	// 改行を削除（unfold）
	v = unfoldHeader(v)
	// タブとスペースを単一のスペースに圧縮
	v = strings.Join(strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == '\t'
	}), " ")
	// 先頭と末尾の空白を削除
	v = strings.TrimSpace(v)
	return k + ":" + v + crlf
}

type crlfFixer struct {
	cr bool
}

func (cf *crlfFixer) Fix(b []byte) []byte {
	res := make([]byte, 0, len(b))
	for _, ch := range b {
		prevCR := cf.cr
		cf.cr = false
		switch ch {
		case '\r':
			cf.cr = true
		case '\n':
			if !prevCR {
				res = append(res, '\r')
			}
		}
		res = append(res, ch)
	}
	return res
}

// ヘッダの正規化を行う関数です。
func Header(s string, canonical Canonicalization) string {
	var result string
	switch canonical {
	case Simple:
		result = SimpleHeader(s)
	case Relaxed:
		result = RelaxedHeader(s)
	default:
		result = SimpleHeader(s)
	}
	return result
}

// bodyCanonicalizer retains only deferred whitespace and line endings. The
// buffer size is independent of both body size and the length of a single line.
type bodyCanonicalizer struct {
	w             *bufio.Writer
	relaxed       bool
	pendingCR     bool
	pendingWSP    bool
	pendingBreaks int64
	hasContent    bool
	closed        bool
	err           error
}

func (c *bodyCanonicalizer) data(ch byte) error {
	if c.relaxed && (ch == ' ' || ch == '\t') {
		c.pendingWSP = true
		return nil
	}
	for c.pendingBreaks > 0 {
		if _, err := c.w.WriteString(crlf); err != nil {
			return err
		}
		c.pendingBreaks--
	}
	if c.pendingWSP {
		if err := c.w.WriteByte(' '); err != nil {
			return err
		}
		c.pendingWSP = false
	}
	c.hasContent = true
	return c.w.WriteByte(ch)
}

func (c *bodyCanonicalizer) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	if c.err != nil {
		return 0, c.err
	}
	for i, ch := range p {
		if c.pendingCR {
			c.pendingCR = false
			if ch != '\n' {
				if c.err = c.data('\r'); c.err != nil {
					return i, c.err
				}
			}
		}
		switch ch {
		case '\r':
			c.pendingCR = true
		case '\n':
			c.pendingWSP = false
			c.pendingBreaks++
		default:
			if c.err = c.data(ch); c.err != nil {
				return i, c.err
			}
		}
	}
	return len(p), nil
}

func (c *bodyCanonicalizer) Close() error {
	if c.closed {
		return c.err
	}
	c.closed = true
	if c.err != nil {
		return c.err
	}
	if c.pendingCR {
		if c.err = c.data('\r'); c.err != nil {
			return c.err
		}
	}
	// Trailing empty lines and relaxed trailing WSP are discarded. Simple
	// always emits one CRLF, including for an empty body; relaxed empty is zero.
	if c.hasContent || !c.relaxed {
		_, c.err = c.w.WriteString(crlf)
	}
	if c.err == nil {
		c.err = c.w.Flush()
	}
	return c.err
}

func SimpleBody(w io.Writer) io.WriteCloser {
	return &bodyCanonicalizer{w: bufio.NewWriter(w)}
}

func RelaxedBody(w io.Writer) io.WriteCloser {
	return &bodyCanonicalizer{w: bufio.NewWriter(w), relaxed: true}
}

func Body(w io.Writer, canon Canonicalization) io.WriteCloser {
	if canon == Relaxed {
		return RelaxedBody(w)
	}
	return SimpleBody(w)
}
