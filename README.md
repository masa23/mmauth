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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The SPF test data in the `spf/pyspf/test` directory includes files with separate licenses:
- `rfc4408-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc4408-tests.LICENSE](spf/pyspf/test/rfc4408-tests.LICENSE) for details.
- `rfc7208-tests.yml` is licensed under a BSD-style license. See [spf/pyspf/test/rfc7208-tests.LICENSE](spf/pyspf/test/rfc7208-tests.LICENSE) for details.
- Other test files are licensed under the Python Software Foundation License Version 2. See [spf/pyspf/LICENSE](spf/pyspf/LICENSE) for details.

## Thanks!

The following library was used as a reference during production.

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
