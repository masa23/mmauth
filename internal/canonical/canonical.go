package canonical

import (
	"io"
	"strings"
)

const crlf = "\r\n"

// シンプルとリラックスの2つの正規化アルゴリズムを定義します。
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
// RFC 5322によると、ヘッダの折り返しはCRLFとそれに続く空白文字(WSP)でのみ構成されます。
func unfoldHeader(s string) string {
	// CRLF+WSPのシーケンスを削除（unfold）
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

type simpleBodyCanonicalizer struct {
	w         io.Writer
	buf       []byte
	crlfFixer crlfFixer
}

func (c *simpleBodyCanonicalizer) Write(b []byte) (int, error) {
	// bufにデータを追加
	c.buf = append(c.buf, b...)
	return len(b), nil
}

func (c *simpleBodyCanonicalizer) Close() error {
	// CRLFを修正
	fixed := c.crlfFixer.Fix(c.buf)

	// 末尾の空行を削除
	for len(fixed) >= 2 && fixed[len(fixed)-2] == '\r' && fixed[len(fixed)-1] == '\n' {
		fixed = fixed[:len(fixed)-2]
	}

	// 末尾にCRLFを追加
	fixed = append(fixed, []byte(crlf)...)

	// データを書き込む
	if _, err := c.w.Write(fixed); err != nil {
		return err
	}

	return nil
}

// ボディをシンプル正規化する関数です。
func SimpleBody(w io.Writer) io.WriteCloser {
	return &simpleBodyCanonicalizer{w: w}
}

type relaxedBodyCanonicalizer struct {
	w         io.Writer
	buf       []byte
	crlfFixer crlfFixer
}

func (c *relaxedBodyCanonicalizer) Write(b []byte) (int, error) {
	// bufにデータを追加
	c.buf = append(c.buf, b...)
	return len(b), nil
}

func (c *relaxedBodyCanonicalizer) Close() error {
	// CRLFを修正
	fixed := c.crlfFixer.Fix(c.buf)

	// 文字列を\r\nで分割して行のスライスを作成
	lines := strings.Split(string(fixed), "\r\n")

	// 最後の空行を削除（スペースやタブのみの行も含む）
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	// 各行を処理
	var canonical []string
	for _, line := range lines {
		// 行末の空白を削除
		for len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			line = line[:len(line)-1]
		}

		// 行内の連続する空白を単一のスペースに圧縮
		var compressedLine []byte
		wsp := false
		for _, ch := range []byte(line) {
			if ch == ' ' || ch == '\t' {
				if !wsp {
					compressedLine = append(compressedLine, ' ')
					wsp = true
				}
			} else {
				compressedLine = append(compressedLine, ch)
				wsp = false
			}
		}

		canonical = append(canonical, string(compressedLine))
	}

	// 結果を結合
	result := strings.Join(canonical, "\r\n")

	// 末尾にCRLFを追加
	result += "\r\n"

	// データを書き込む
	if _, err := c.w.Write([]byte(result)); err != nil {
		return err
	}

	return nil
}

// ボディをリラックス正規化する関数です。
func RelaxedBody(w io.Writer) io.WriteCloser {
	return &relaxedBodyCanonicalizer{w: w}
}

// ボディの正規化を行う関数です。
func Body(w io.Writer, canonical Canonicalization) io.WriteCloser {
	switch canonical {
	case Simple:
		return SimpleBody(w)
	case Relaxed:
		return RelaxedBody(w)
	default:
		return SimpleBody(w)
	}
}
