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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Thanks!

The following library was used as a reference during production.

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
