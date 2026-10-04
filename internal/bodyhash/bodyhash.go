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
	return NewBodyHashWithLimit(canon, hashAlgo, limit, false)
}

// NewBodyHashWithLimit distinguishes explicit l=0 from an omitted length.
// Positive limits remain effective even when limitSet is false.
func NewBodyHashWithLimit(canon canonical.Canonicalization, hashAlgo crypto.Hash, limit int64, limitSet bool) *BodyHash {
	bh := NewCanonicalizedBodyHash(hashAlgo, limit, limitSet)
	bh.w = canonical.Body(bh.w, canon)
	return bh
}

type writerCloser struct{ io.Writer }

func (writerCloser) Close() error { return nil }

// NewCanonicalizedBodyHash consumes already canonicalized bytes, allowing
// callers to share a canonicalizer among multiple hash/length combinations.
func NewCanonicalizedBodyHash(hashAlgo crypto.Hash, limit int64, limitSet bool) *BodyHash {
	hasher := hashAlgo.New()
	var writer io.Writer = hasher
	if limit > 0 || (limitSet && limit == 0) {
		writer = newLimitWriter(writer, limit)
	}
	return &BodyHash{hashAlgo: hashAlgo, hasher: hasher, w: writerCloser{writer}}
}
