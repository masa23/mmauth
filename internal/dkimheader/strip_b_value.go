package dkimheader

import (
	"strings"
)

// StripBValueForSigning removes the value of the b= tag from a DKIM-Signature header
// while preserving all other formatting including whitespace and folding.
// This is required for signature calculation as per RFC 6376 §3.5 and §3.7.
//
// This function takes a raw header line (including DKIM-Signature: ...\\r\\n)
// and returns a new string with the b= tag value removed but all other
// formatting preserved.
func StripBValueForSigning(rawHeaderLine string) string {
	// Find the start of the b= tag (case insensitive)
	bTagStart := findBTagStart([]rune(rawHeaderLine))
	if bTagStart == -1 {
		// No b= tag found, return original
		return rawHeaderLine
	}

	// Find the end of the b= tag value
	bTagEnd := findBTagEnd([]rune(rawHeaderLine), bTagStart)
	if bTagEnd == -1 {
		// Malformed b= tag, return original
		return rawHeaderLine
	}

	// Build result by combining:
	// 1. Part before b= value (including "b=" or "B=")
	// 2. Empty b= value (just "b=")
	// 3. Part after b= value
	var result strings.Builder
	result.Grow(len(rawHeaderLine) - (bTagEnd - bTagStart)) // Pre-allocate approximate capacity

	// Add part before b= value, including the b= tag itself
	result.WriteString(rawHeaderLine[:bTagStart])

	// Add part after b= value
	if bTagEnd < len(rawHeaderLine) {
		result.WriteString(rawHeaderLine[bTagEnd:])
	}

	return result.String()
}

// findBTagStart finds the start position of the b= tag value
// Returns the index after "b=" where the value starts, or -1 if not found
func findBTagStart(runes []rune) int {
	// Look for b= tag (case insensitive)
	for i := 0; i < len(runes)-1; i++ {
		// Check for possible b= tag start
		if (runes[i] == 'b' || runes[i] == 'B') && runes[i+1] == '=' {
			// Make sure it's preceded by ; or whitespace (or is at the beginning of the header value)
			if i == 0 || runes[i-1] == ';' || isFWS(runes[i-1]) {
				return i + 2 // Position after "b="
			}
		}
	}
	return -1
}

// findBTagEnd finds the end position of the b= tag value
// Starting from bTagStart (after "b="), find where the value ends
// Returns the index where the value ends (either at semicolon or end of line)
func findBTagEnd(runes []rune, bTagStart int) int {
	i := bTagStart

	// Skip any leading FWS after b=
	for i < len(runes) && isFWS(runes[i]) {
		i++
	}

	// Scan through the value
	// The value consists of base64 characters and FWS
	for i < len(runes) {
		// Handle folded headers (CRLF + WSP)
		if i+2 < len(runes) && runes[i] == '\r' && runes[i+1] == '\n' && isFWS(runes[i+2]) {
			// Skip the CRLF and WSP (folded header continuation)
			i += 3
			continue
		}

		// Stop at semicolon or end of line
		if runes[i] == ';' || runes[i] == '\r' || runes[i] == '\n' {
			break
		}
		i++
	}

	return i
}

// isFWS checks if a rune is considered Folding White Space (FWS)
// FWS = 1*WSP / obs-FWS (RFC 5322)
// obs-FWS = 1*WSP *(CRLF 1*WSP)
func isFWS(r rune) bool {
	return r == ' ' || r == '\t'
}
