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
