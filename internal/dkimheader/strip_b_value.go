package dkimheader

import "strings"

// StripBValueForSigning removes the b tag value, including its surrounding
// FWS, while preserving the tag name, equals sign and other header bytes.
func StripBValueForSigning(raw string) string {
	start := 0
	if colon := strings.IndexByte(raw, ':'); colon >= 0 {
		start = colon + 1
	}
	for start < len(raw) {
		end := strings.IndexByte(raw[start:], ';')
		if end < 0 {
			end = len(raw)
		} else {
			end += start
		}
		part := raw[start:end]
		eq := strings.IndexByte(part, '=')
		if eq >= 0 && strings.EqualFold(strings.Trim(part[:eq], " \t\r\n"), "b") {
			valueEnd := end
			// Keep the header field terminator, but remove folded value lines.
			if end == len(raw) {
				if strings.HasSuffix(raw, "\r\n") {
					valueEnd -= 2
				} else if strings.HasSuffix(raw, "\n") {
					valueEnd--
				}
			}
			return raw[:start+eq+1] + raw[valueEnd:]
		}
		start = end + 1
	}
	return raw
}
