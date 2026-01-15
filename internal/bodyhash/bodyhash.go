package bodyhash

// bodyhash bh=を計算する

import (
	"crypto"
	_ "crypto/sha1"   // sha1を使う
	_ "crypto/sha256" // sha256を使う
	"encoding/base64"
	"hash"
	"io"

	"github.com/masa23/mmauth/internal/canonical"
)

type BodyHash struct {
	hashAlgo crypto.Hash
	w        io.WriteCloser
	hasher   hash.Hash
	limit    int64
}

// メール本文の書き込みを行う
// ハッシュ値を計算する
func (b *BodyHash) Write(p []byte) (n int, err error) {
	return b.w.Write(p)
}

// メール本文の書き込みを終了する
func (b *BodyHash) Close() error {
	return b.w.Close()
}

// ハッシュ値を取得する
// 取得前にClose()を呼ぶこと
func (b *BodyHash) Get() string {
	hash := b.hasher.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}

// Canonicalizationとハッシュアルゴリズムを指定してBodyHasherを生成する
func NewBodyHash(canon canonical.Canonicalization, hashAlgo crypto.Hash, limit int64) *BodyHash {
	if limit < 0 {
		limit = 0
	}
	hasher := hashAlgo.New()
	bh := &BodyHash{
		hashAlgo: hashAlgo,
		hasher:   hasher,
		limit:    limit,
	}

	// limitWriterを介してcanonicalizerに接続する
	// canonicalization -> limitWriter -> hasher
	var writer io.Writer = hasher
	if limit > 0 {
		writer = newLimitWriter(writer, limit)
	}

	switch canon {
	case canonical.Simple:
		bh.w = canonical.SimpleBody(writer)
	case canonical.Relaxed:
		bh.w = canonical.RelaxedBody(writer)
	default:
		// 指定が不明の場合はSimpleを使う
		bh.w = canonical.SimpleBody(writer)
	}
	return bh
}
