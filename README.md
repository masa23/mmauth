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

### Provisional verification and DSNs

`dkim2.VerifyProvisional(raw, envelope, verification)` implements draft-09 section 13.2. It checks only the latest signature, current message hashes, timestamp and SMTP envelope. Its separate `ProvisionalResult` must not be treated as a full-chain `Verify` result. Historical fields must still be syntactically parseable. A successful out-of-band `nd=` arrangement is marked `PendingNextDomain`; standard DSN generation refuses that pending state. Provisional verification never calls the replay store.

The DSN APIs implement draft-09 section 16 without sending mail or changing ordinary mmauth verification:

```go
report, err := dkim2.CreateDSN(receivedWire, receivedEnvelope, dkim2.DSNOptions{
    Sign: dkim2.SignOptions{Domain: "destination.test", Selector: "s1", Key: privateKey},
    Verify: verification,
    Recipients: []dkim2.DSNRecipient{{
        FinalRecipient: "<bob@destination.test>",
        Action: "failed", Status: "5.1.1", Diagnostic: "550 unknown user",
    }},
})
// On success, deliver report.Wire with exactly report.Envelope.

checked := dkim2.VerifyDSN(dsnWire, dsnEnvelope, dkim2.DSNVerifyOptions{
    Verification: verification,
    LocalDomains: []string{"relay.test"}, // Exact signing domains used locally.
})
// Inspect checked.Status, checked.Authentication and local delivery policy.
```

`CreateDSN` authenticates the received message provisionally, derives a null MAIL FROM and the return recipient from the authenticated latest hop, and checks the DSN signing domain against the original recipients. Never set `DSNOptions.Sign.Envelope` or `NextDomain`: these are derived by the DSN API. `Recipients` must describe real delivery outcomes for actual recipients; no failure status is invented. `HeadersOnly` selects `text/rfc822-headers` instead of the unchanged original `message/rfc822` MIME part. A null original MAIL FROM is always rejected to prevent notification loops.

`VerifyDSN` authenticates the DSN itself and the embedded original's latest signature and hashes, confirms the local sending identity and DSN origin, and checks the return address. `HeadersOnly` explicitly records when the omitted body was not checked. A `None`, `Fail`, `PermError` or `TempError` result must not be propagated. DNS lookup/time limits cover both outer and embedded verification. The human-readable MIME part accepts `text/*` and opaque `multipart/alternative` presentations; the library does not render them.

Internationalized DSNs also support the `message/global`, `message/global-headers`, and `message/global-delivery-status` types from [RFC 6533](https://www.rfc-editor.org/rfc/rfc6533.html#section-4.4). When the attached original contains 8-bit octets, generation selects `message/global`, or `message/global-headers` for headers-only returns, and base64 encodes the exact original bytes. All-ASCII attachments keep the traditional types. The MTA must use SMTPUTF8 when the returned envelope or outer DSN headers contain internationalized addresses.

Recipe copy bounds follow JSON Schema integer semantics: `1`, `1.0`, and `1e0` can represent the same integer. Non-integral values and integers outside the supported range are rejected without floating-point rounding.

To propagate a DSN, call `dkim2.PropagateDSN` with `DSNPropagationOptions`. Supply `Verification`, fresh `Notification` content, and `ReceivedSignatureIndex`: the highest original signature index recorded when this particular message arrived, before this forwarder added its signatures. Bind that metadata to the message in your MTA; do not accept the cutoff from an unauthenticated report. The API removes only signatures belonging to `LocalDomains`, reverses the relevant Recipes, removes unsigned routing fields, and issues a new DSN with one signature and one Message-Instance. A null Recipe forces headers-only output. Provide upstream-safe human text, diagnostics and recipient results: downstream report text is never copied automatically. The MTA remains responsible for SMTP transmission, retries and replay/delivery policy.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The SPF test data in the `spf/pyspf/test` directory includes files with separate licenses:
- `rfc4408-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc4408-tests.LICENSE](spf/pyspf/test/rfc4408-tests.LICENSE) for details.
- `rfc7208-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc7208-tests.LICENSE](spf/pyspf/test/rfc7208-tests.LICENSE) for details.
- Other test files are licensed under the Python Software Foundation License Version 2. See [spf/pyspf/LICENSE](spf/pyspf/LICENSE) for details.

## Thanks!

The following library was used as a reference during production.

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
