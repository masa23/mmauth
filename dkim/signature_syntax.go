package dkim

import (
	"fmt"
	"strings"
)

// decodeDKIMIdentity removes FWS and decodes DKIM quoted-printable. The
// decoded local-part is then checked separately against SMTP mailbox syntax.
func decodeDKIMIdentity(value string) (string, error) {
	value = stripFWS(value)
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '=' {
			if i+2 >= len(value) {
				return "", fmt.Errorf("incomplete DKIM quoted-printable escape")
			}
			hi, lo := upperHex(value[i+1]), upperHex(value[i+2])
			if hi < 0 || lo < 0 {
				return "", fmt.Errorf("invalid DKIM quoted-printable escape")
			}
			out.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		if ch < '!' || ch > '~' || ch == ';' {
			return "", fmt.Errorf("invalid DKIM quoted-printable character")
		}
		out.WriteByte(ch)
	}
	return out.String(), nil
}

// encodeDKIMIdentity applies RFC 6376 §2.11 to a semantic AUID when writing
// the i= tag. In particular, an unencoded semicolon would end the tag value.
func encodeDKIMIdentity(value string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= '!' && ch <= ':') || ch == '<' || (ch >= '>' && ch <= '~') {
			out.WriteByte(ch)
			continue
		}
		out.WriteByte('=')
		out.WriteByte(hex[ch>>4])
		out.WriteByte(hex[ch&0x0f])
	}
	return out.String()
}

func upperHex(ch byte) int {
	if ch >= '0' && ch <= '9' {
		return int(ch - '0')
	}
	if ch >= 'A' && ch <= 'F' {
		return int(ch-'A') + 10
	}
	return -1
}

func validDKIMLocalPart(local string) bool {
	if local == "" {
		return true
	}
	if local[0] == '"' {
		if len(local) < 2 || local[len(local)-1] != '"' {
			return false
		}
		for i := 1; i < len(local)-1; i++ {
			ch := local[i]
			if ch == '\\' {
				i++
				if i == len(local)-1 || local[i] < ' ' || local[i] > '~' {
					return false
				}
				continue
			}
			if ch < ' ' || ch > '~' || ch == '"' {
				return false
			}
		}
		return true
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		ch := local[i]
		if ch == '.' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", rune(ch)) {
			continue
		}
		return false
	}
	return true
}
