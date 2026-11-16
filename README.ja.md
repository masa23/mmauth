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

DKIM2検証では、メール1通につきDNS照会32回、DNS処理15秒を既定の上限とします。`dkim2.VerifyOptions.MaxDNSLookups`と`DNSBudget`で調整できます。受信した署名を検証せずに追加署名する取り決めがある場合に限り、`Forward`・`Revise`で`SignOptions.OutOfBandArrangement = true`を指定します。通常の転送には`ForwardChecked`・`ReviseChecked`を使用します。不正なDKIM・ARCヘッダーの扱いや署名数上限は既存の処理を維持します。既存処理で`Close`がエラーとなる場合も、メール全体を保持できた場合は、その後`Verify`を呼ぶことでDKIM2の結果を独立して取得できます。

`dkim2`単体にも、メッセージ32 MiB、ヘッダー合計1 MiB、1フィールド64 KiB、4096フィールドの上限があります。保持上限を引き上げても、この解析上限は変わりません。RSA鍵は1024〜8192bit、指数65537に制限します。国際化ドメインは有効なIDNAのA-label・U-labelを使用し、互換文字による表記、不正UTF-8、ASCIIだけに復号されるPunycodeラベルは拒否します。小文字化するのは全体がASCIIのラベルだけです。U-labelには大小文字変換を加えず、有効なNFC文字列を要求します。例えば`BÜCHER.example`ではなく、`bücher.example`または対応するA-labelを使用してください。

BCCを含む送信では、論理的な配送全体のBCC宛先SMTPパスを`SignOptions.BCCRecipients`に渡し、通常宛先用とBCC宛先用を別コピー・別SMTPトランザクションに分け、それぞれ実際の`Envelope`で署名してください。申告したBCC宛先と通常宛先の混在は拒否します。値のある`Bcc`・`Resent-Bcc`ヘッダーは署名前に削除してください。削除後はライブラリがBCCを推測できないため、呼び出し側からのメタデータ指定が必要です。そのコピーのエンベロープに含まれないBCCメタデータは出力されません。

`VerifyOptions.ReplayCheck`は完全な認証後、`exploded`の有無にかかわらず呼び出します。配送ポリシーでは`Result.ReplayDetected`・`ReplayErr`・`ExplodedAt`を評価してください。`ExplodedAt`には複数配送を申告した署名番号とドメインが入ります。認証結果`pass`だけで配送を許可するものではありません。

### 暫定検証とDSN

`dkim2.VerifyProvisional(raw, envelope, verification)`でdraft-09 §13.2の暫定検証を行います。最新署名・現在のメッセージハッシュ・時刻・SMTPエンベロープだけを検証します。戻り値は独立した`ProvisionalResult`であり、その`Pass`を完全検証の成功とみなさないでください。過去のフィールドにも解析可能な構文を要求します。取り決めにより最高位の`nd=`を受理した場合は`PendingNextDomain`が立ち、その状態での標準DSN生成は拒否します。暫定検証はリプレイストアを呼び出しません。

draft-09 §16のDSNは、次の明示的なAPIで扱います。SMTP送信そのものや通常のmmauth検証処理は変更しません。

```go
report, err := dkim2.CreateDSN(receivedWire, receivedEnvelope, dkim2.DSNOptions{
    Sign: dkim2.SignOptions{Domain: "destination.test", Selector: "s1", Key: privateKey},
    Verify: verification,
    Recipients: []dkim2.DSNRecipient{{
        FinalRecipient: "<bob@destination.test>",
        Action: "failed", Status: "5.1.1", Diagnostic: "550 unknown user",
    }},
})
// 成功時、report.Wireをreport.EnvelopeどおりのSMTPエンベロープで配送する。

checked := dkim2.VerifyDSN(dsnWire, dsnEnvelope, dkim2.DSNVerifyOptions{
    Verification: verification,
    LocalDomains: []string{"relay.test"}, // 自システムが実際に使う署名ドメイン。
})
// checked.Status・checked.Authenticationとローカル配送ポリシーを評価する。
```

`CreateDSN`は受信メールの暫定検証を必須とし、認証した最新ホップから返送先を決め、null MAIL FROMの署名済み3部構成MIME通知を生成します。DSNの署名ドメインと元メールの宛先ドメインの関係も確認します。`DSNOptions.Sign.Envelope`・`NextDomain`は指定せず、APIによる導出に任せてください。`Recipients`には実際の受信宛先についての正しい配送結果を指定します。ライブラリが失敗情報を捏造することはありません。`HeadersOnly`で原文全体の`message/rfc822`の代わりに`text/rfc822-headers`を選べます。元メールのMAIL FROMがnullなら、通知ループを防ぐため生成を拒否します。

`VerifyDSN`はDSN自体と埋め込み原文の最新署名・ハッシュを認証し、自システムの署名ドメイン・MAIL FROM、DSN発信者、実際の返送宛先を確認します。本文を含まない場合は`HeadersOnly`で明示します。`None`・`Fail`・`PermError`・`TempError`の通知は上流へ伝播させないでください。DNS照会数・時間はDSN本体と原文を合算して制限します。受信MIMEの人間向け部分は`text/*`と、内部構造を解釈しない`multipart/alternative`に対応し、内容の表示処理は行いません。

国際化DSNでは[RFC6533](https://www.rfc-editor.org/rfc/rfc6533.html#section-4.4)の`message/global`・`message/global-headers`・`message/global-delivery-status`にも対応します。生成時、添付する原文に8bitオクテットがあれば`message/global`、ヘッダーのみなら`message/global-headers`を選び、base64で元のバイト列を保持します。ASCIIのみの添付は従来の形式を使用します。返送エンベロープやDSN本体のヘッダーに国際化アドレスが含まれる場合、MTA側でSMTPUTF8を使用してください。

Recipeのコピー範囲はJSON Schemaの整数として解釈し、`1`・`1.0`・`1e0`など同じ整数を表す数値を受理します。非整数や扱える整数範囲を超える値は、浮動小数で丸めずに拒否します。

上流への伝播には`dkim2.PropagateDSN`と`DSNPropagationOptions`を使います。`Verification`、新しい通知内容の`Notification`、元メールをこの転送システムが受信した時点の最高署名番号`ReceivedSignatureIndex`を指定してください。この番号はメールと対応付けてMTA側に保存し、未認証の通知から採用しないでください。APIは`LocalDomains`に属する追加署名だけを除去し、該当Recipeを逆適用し、未署名の経路フィールドを削除したうえで、署名とMessage-Instanceがそれぞれ1個の新しいDSNを生成します。null Recipeがあればヘッダーのみの通知に切り替えます。人間向け文面・診断・配送結果には上流へ開示してよい内容を指定してください。下流DSNの文面は自動転記しません。SMTP送信、再送、リプレイ・配送判断はMTA側の責任です。

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
