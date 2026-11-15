# mmauth [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/mmauth)](https://goreportcard.com/report/github.com/masa23/mmauth) [![GoDoc](https://godoc.org/github.com/masa23/mmauth?status.svg)](https://godoc.org/github.com/masa23/mmauth) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/mmauth/main/LICENSE)

* [日本語](README.ja.md)
* [English](README.md)

A Go library for DKIM and ARC signing.  
It aims to comply with [RFC6376](https://datatracker.ietf.org/doc/html/rfc6376) and [RFC8617](https://datatracker.ietf.org/doc/html/rfc8617).

## Features

- **DKIM** signing for outgoing messages  
- Adds **ARC** chains for forwarded messages

## Installation

```bash
go get github.com/masa23/mmauth
```

## Usage

* [arcmilter](https://github.com/masa23/arcmilter) is a milter implementation that uses this library.

### Opt in to DKIM2 verification

`NewMMAuth()` keeps DKIM2 disabled. Enable it for an SMTP transaction with the actual envelope paths:

```go
m, err := mmauth.NewMMAuthWithOptions(mmauth.MMAuthOptions{
    EnableDKIM2: true,
    DKIM2Envelope: dkim2.Envelope{
        MailFrom: "<alice@example.com>",
        RcptTo:   []string{"<bob@example.net>"},
    },
})
if err != nil { /* configuration error */ }
_, err = m.Write(rawMessage) // Original message bytes from SMTP.
if err != nil { /* write error */ }
if err := m.Close(); err != nil { /* input error */ }
m.Verify()
outcome := m.GetDKIM2Verification()
// Check outcome.Result.Status when outcome.Checked is true.
// outcome.Err reports local errors such as the capture limit.
```

Only enabled messages with DKIM2 fields are kept in memory, up to 32 MiB by default. Set `DKIM2MaxMessageBytes` to change the limit. Exceeding it does not stop the existing DKIM or ARC processing. `GetAuthenticationHeader` adds `dkim2=...` only after DKIM2 was checked. Outgoing DKIM2 signing remains an explicit call to `dkim2.Sign`, `dkim2.ForwardChecked`, or `dkim2.ReviseChecked`.

DKIM2 verification allows 32 DNS lookups and 15 seconds of DNS time per message by default; `dkim2.VerifyOptions.MaxDNSLookups` and `DNSBudget` can adjust these limits. `Forward` and `Revise` require `SignOptions.OutOfBandArrangement = true` for an explicit arrangement that permits signing without verifying the incoming chain. Use `ForwardChecked` and `ReviseChecked` for ordinary forwarding. A malformed DKIM or ARC header still causes the existing `Close` error; after `Close`, `Verify` can independently report DKIM2 when its complete input was captured.

The standalone DKIM2 parser also limits messages to 32 MiB, headers to 1 MiB in total, each header field to 64 KiB, and header count to 4096. Raising the adapter's capture limit does not raise these parser limits. RSA keys must be 1024–8192 bits with exponent 65537. Internationalized domains must be valid IDNA A-labels or U-labels; compatibility forms, invalid UTF-8, and ASCII-only Punycode labels are rejected. Only entirely ASCII labels are lowercased. U-labels must already be valid NFC strings and are never case-folded; for example, use `bücher.example` or its A-label rather than `BÜCHER.example`.

For outgoing BCC delivery, populate `SignOptions.BCCRecipients` with all blind-recipient SMTP paths of the logical delivery, split ordinary and blind recipients into separate copies and SMTP transactions, and sign each copy with its own `Envelope`. Mixing declared BCC and ordinary recipients is rejected. Remove populated `Bcc` and `Resent-Bcc` headers before signing. Once those headers are removed, the library cannot infer BCC recipients, so the caller must supply this metadata. BCC metadata outside the copy's envelope is not written into the message.

`VerifyOptions.ReplayCheck` runs after full authentication, including for messages with `exploded`. Evaluate `Result.ReplayDetected`, `ReplayErr`, and `ExplodedAt` in your delivery policy; `ExplodedAt` identifies the signature index and domain of each signer claiming multiple delivery. Authentication `pass` alone does not authorize delivery.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The SPF test data in the `spf/pyspf/test` directory includes files with separate licenses:
- `rfc4408-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc4408-tests.LICENSE](spf/pyspf/test/rfc4408-tests.LICENSE) for details.
- `rfc7208-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc7208-tests.LICENSE](spf/pyspf/test/rfc7208-tests.LICENSE) for details.
- Other test files are licensed under the Python Software Foundation License Version 2. See [spf/pyspf/LICENSE](spf/pyspf/LICENSE) for details.

## Thanks!

The following library was used as a reference during production.

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
