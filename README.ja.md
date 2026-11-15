# mmauth [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/mmauth)](https://goreportcard.com/report/github.com/masa23/mmauth) [![GoDoc](https://godoc.org/github.com/masa23/mmauth?status.svg)](https://godoc.org/github.com/masa23/mmauth) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/mmauth/main/LICENSE)

* [日本語](README.ja.md)
* [English](README.md)

DKIM署名、ARC署名を行うGoライブラリです。  
[RFC6376](https://datatracker.ietf.org/doc/html/rfc6376)、[RFC8617](https://datatracker.ietf.org/doc/html/rfc8617)、に準拠することを目指しています。

## 特長

- **DKIM** による送信メールの署名
- 転送時に **ARC** チェーンを追加

## インストール

```bash
 go get github.com/masa23/mmauth
```

## 使用例

* [arcmilter](https://github.com/masa23/arcmilter) はこのライブラリを利用したmilterの実装です。

### DKIM2の検証を有効にする

`NewMMAuth()` は従来どおりDKIM2を検証しません。SMTPトランザクションごとに明示的に有効にできます。

```go
m, err := mmauth.NewMMAuthWithOptions(mmauth.MMAuthOptions{
    EnableDKIM2: true,
    DKIM2Envelope: dkim2.Envelope{
        MailFrom: "<alice@example.com>",
        RcptTo:   []string{"<bob@example.net>"},
    },
})
if err != nil { /* 設定エラー */ }
_, err = m.Write(rawMessage) // SMTPで受け取ったメールの生データ
if err != nil { /* 書き込みエラー */ }
if err := m.Close(); err != nil { /* 読み込みエラー */ }
m.Verify()
outcome := m.GetDKIM2Verification()
// outcome.Checkedならoutcome.Result.Statusを確認する。
// outcome.Errはメッセージ保持上限などのローカルエラー。
```

DKIM2は受信メールの生データ全体を使います。有効時のみ、DKIM2フィールドがあるメールを最大32 MiBまでメモリに保持します。`DKIM2MaxMessageBytes`で上限を変更できます。上限を超えても従来のDKIM・ARC検証は継続します。`GetAuthenticationHeader`には、DKIM2を実際に検証した場合のみ`dkim2=...`が追加されます。送信時のDKIM2署名は`dkim2`パッケージの`Sign`、`ForwardChecked`、`ReviseChecked`を明示的に使用してください。

DKIM2検証では、メール1通につきDNS照会32回、DNS処理15秒を既定の上限とします。`dkim2.VerifyOptions.MaxDNSLookups`と`DNSBudget`で調整できます。受信した署名を検証せずに追加署名する取り決めがある場合に限り、`Forward`・`Revise`で`SignOptions.OutOfBandArrangement = true`を指定します。通常の転送には`ForwardChecked`・`ReviseChecked`を使用します。不正なDKIM・ARCヘッダーに対する従来の`Close`エラーは維持されますが、メール全体を保持できた場合は、その後`Verify`を呼ぶことでDKIM2の結果を独立して取得できます。

`dkim2`単体にも、メッセージ32 MiB、ヘッダー合計1 MiB、1フィールド64 KiB、4096フィールドの上限があります。保持上限を引き上げても、この解析上限は変わりません。RSA鍵は1024〜8192bit、指数65537に制限します。国際化ドメインは有効なIDNAのA-label・U-labelを使用し、互換文字による表記、不正UTF-8、ASCIIだけに復号されるPunycodeラベルは拒否します。

BCCを含む送信では、論理的な配送全体のBCC宛先SMTPパスを`SignOptions.BCCRecipients`に渡し、通常宛先用とBCC宛先用を別コピー・別SMTPトランザクションに分け、それぞれ実際の`Envelope`で署名してください。申告したBCC宛先と通常宛先の混在は拒否します。値のある`Bcc`・`Resent-Bcc`ヘッダーは署名前に削除してください。削除後はライブラリがBCCを推測できないため、呼び出し側からのメタデータ指定が必要です。そのコピーのエンベロープに含まれないBCCメタデータは出力されません。

`VerifyOptions.ReplayCheck`は完全な認証後、`exploded`の有無にかかわらず呼び出します。配送ポリシーでは`Result.ReplayDetected`・`ReplayErr`・`ExplodedAt`を評価してください。`ExplodedAt`には複数配送を申告した署名番号とドメインが入ります。認証結果`pass`だけで配送を許可するものではありません。

## ライセンス

このプロジェクトは MIT ライセンスのもとで公開されています。詳細は [LICENSE](LICENSE) ファイルをご覧ください。

### SPF テストデータのライセンス

`spf/pyspf/test` ディレクトリにある SPF テストデータには別々のライセンスが付与されています:
- `rfc4408-tests.yml` は BSD 系ライセンスです。詳細は [spf/pyspf/test/rfc4408-tests.LICENSE](spf/pyspf/test/rfc4408-tests.LICENSE) を参照してください。
- `rfc7208-tests.yml` は BSD 系ライセンスです。詳細は [spf/pyspf/test/rfc7208-tests.LICENSE](spf/pyspf/test/rfc7208-tests.LICENSE) を参照してください。
- その他のテストファイルは Python Software Foundation License Version 2 の下でライセンスされています。詳細は [spf/pyspf/LICENSE](spf/pyspf/LICENSE) を参照してください。

## Thanks!

以下のライブラリは制作に当たって参考にさせていただきました。

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
