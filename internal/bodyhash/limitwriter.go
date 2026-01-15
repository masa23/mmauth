package bodyhash

import (
	"io"
)

// limitWriter は io.Writer をラップし、指定されたバイト数までしか書き込まないように制限します。
type limitWriter struct {
	w     io.Writer
	limit int64
}

// Write は p を基底の Writer に書き込みますが、limit を超える部分は破棄します。
func (lw *limitWriter) Write(p []byte) (n int, err error) {
	if lw.limit <= 0 {
		// 制限が既に達成されている場合は何も書き込まずに成功を返す
		return len(p), nil
	}

	// 書き込むべきバイト数を計算
	toWrite := int64(len(p))
	if toWrite > lw.limit {
		toWrite = lw.limit
	}

	// 実際に書き込む
	n, err = lw.w.Write(p[:toWrite])

	// 書き込んだ分だけ制限を減らす
	lw.limit -= int64(n)

	// 元のデータの長さを返す（呼び出し元はすべて書き込まれたと認識する）
	return len(p), err
}

// newLimitWriter は指定された io.Writer と制限バイト数で limitWriter を作成します。
func newLimitWriter(w io.Writer, limit int64) *limitWriter {
	if limit < 0 {
		limit = 0
	}
	return &limitWriter{
		w:     w,
		limit: limit,
	}
}
