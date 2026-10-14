package bodyhash

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/masa23/mmauth/internal/canonical"
)

// RFC6376の例に基づいたテストケース
// l= タグは canonicalization 後の本文に適用されることを確認する
func TestBodyHashWithRelaxedCanonicalizationAndLimit(t *testing.T) {
	// RFC6376 3.4.4節の例を使用
	// 元の本文: "Test  \r\n\r\n\r\n"
	// relaxed canonicalization後の本文: "Test\r\n"
	// この場合、l=4 とすると "Test" のみがハッシュに含まれるべき

	testCases := []struct {
		name             string
		body             string
		canonicalization canonical.Canonicalization
		hashAlgo         crypto.Hash
		limit            int64
		want             string
	}{
		{
			name:             "rfc6376_relaxed_body_with_limit_4",
			body:             "Test  \r\n\r\n\r\n", // 元の本文
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA256,
			limit:            4,                                              // canonicalization後の "Test" の長さ
			want:             "Uy6qvZV0iA2/drm4zACDLCCm7BE9aCKZVQ16bg80XiU=", // "Test" のSHA256ハッシュのBase64エンコード
		},
		{
			name:             "rfc6376_relaxed_body_with_limit_5",
			body:             "Test  \r\n\r\n\r\n", // 元の本文
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA256,
			limit:            5,                                              // canonicalization後の "Test" + "\r" の長さ
			want:             "KCUDYh74+flYXTn9al83JsyOBrUP9b07hSy8u6j/Qqs=", // "Test\r" のSHA256ハッシュのBase64エンコード
		},
		{
			name:             "rfc6376_simple_body_with_limit_4",
			body:             "Test\r\n", // 元の本文
			canonicalization: canonical.Simple,
			hashAlgo:         crypto.SHA256,
			limit:            4,                                              // "Test" の長さ
			want:             "Uy6qvZV0iA2/drm4zACDLCCm7BE9aCKZVQ16bg80XiU=", // "Test" のSHA256ハッシュのBase64エンコード
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bh := NewBodyHash(tc.canonicalization, tc.hashAlgo, tc.limit)
			bh.Write([]byte(tc.body))
			bh.Close()
			got := bh.Get()
			if got != tc.want {
				t.Errorf("want %s, but got %s", tc.want, got)
			}
		})
	}
}

// SHA256ハッシュ "Test" のBase64エンコードを計算するための補助テスト
func TestBase64EncodeTestStringSHA256(t *testing.T) {
	// このテストは、期待値を計算するために使用されます。
	// 実際のテストではこの値を直接使用します。
	hasher := crypto.SHA256.New()
	hasher.Write([]byte("Test"))
	hash := hasher.Sum(nil)
	encoded := base64.StdEncoding.EncodeToString(hash)
	t.Logf("Base64 encoded SHA256 hash of 'Test': %s", encoded)
}
