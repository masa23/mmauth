package dkimheader

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseSignatureParams parses DKIM-Signature header parameters with strict validation
// according to RFC 6376 requirements.
func ParseSignatureParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)

	// Track seen tags to detect duplicates
	seenTags := make(map[string]bool)

	for _, pair := range pairs {
		trimmedPair := strings.TrimSpace(pair)
		if trimmedPair == "" {
			continue
		}

		key, value, ok := strings.Cut(trimmedPair, "=")
		if !ok {
			return nil, errors.New("malformed header params")
		}

		trimmedKey := strings.ToLower(strings.TrimSpace(key))

		// Check for empty tag name
		if trimmedKey == "" {
			return nil, errors.New("malformed header params")
		}

		// Check for excessively long tag name
		if len(trimmedKey) > 100 {
			return nil, errors.New("malformed header params")
		}

		// Check for excessively long tag value
		trimmedValue := strings.TrimSpace(value)
		if len(trimmedValue) > 1000 {
			return nil, errors.New("malformed header params")
		}

		// Check for duplicate tags (RFC 6376 §3.2 requires meticulous validation)
		if seenTags[trimmedKey] {
			return nil, fmt.Errorf("duplicate tag '%s' in DKIM-Signature header", trimmedKey)
		}
		seenTags[trimmedKey] = true

		// According to RFC 6376 §3.2, unrecognized tags MUST be ignored
		// Only process recognized tags
		if isValidDKIMTag(trimmedKey) {
			params[trimmedKey] = trimmedValue
		}
	}

	// Validate required tags for DKIM-Signature according to RFC 6376
	// All of the following tags are required: a, b, bh, d, h, s, v
	// Note: v is explicitly required according to RFC 6376 Section 3.5
	requiredTags := []string{"a", "b", "bh", "d", "h", "s", "v"}
	for _, tag := range requiredTags {
		if _, exists := params[tag]; !exists {
			return nil, fmt.Errorf("required tag '%s' is missing in DKIM-Signature header", tag)
		}
	}

	// Validate v tag value (RFC 6376 requires version to be "1")
	if params["v"] != "1" {
		return nil, fmt.Errorf("invalid version tag value: %s", params["v"])
	}

	// Type validation for specific tags
	if err := validateTagTypes(params); err != nil {
		return nil, err
	}

	return params, nil
}

// isValidDKIMTag checks if a tag is a recognized DKIM-Signature tag according to RFC 6376
func isValidDKIMTag(tag string) bool {
	// Valid DKIM-Signature tags as defined in RFC 6376 §3.5
	validTags := map[string]bool{
		"v":  true, // Version
		"a":  true, // Algorithm
		"b":  true, // Signature
		"bh": true, // Body hash
		"c":  true, // Canonicalization
		"d":  true, // Domain
		"h":  true, // Headers
		"i":  true, // Identity
		"l":  true, // Length
		"q":  true, // Query
		"s":  true, // Selector
		"t":  true, // Timestamp
		"x":  true, // Expiration
		"z":  true, // Copied headers
	}
	_, exists := validTags[tag]
	return exists
}

// validateTagTypes performs type checking for DKIM-Signature tags
func validateTagTypes(params map[string]string) error {
	// Validate t and x tags (timestamps) - must be integers
	if tVal, exists := params["t"]; exists {
		if _, err := strconv.ParseInt(tVal, 10, 64); err != nil {
			return fmt.Errorf("invalid timestamp 't' value: %s", tVal)
		}
	}

	if xVal, exists := params["x"]; exists {
		if _, err := strconv.ParseInt(xVal, 10, 64); err != nil {
			return fmt.Errorf("invalid expiration 'x' value: %s", xVal)
		}
	}

	// Validate l tag (body length) - must be non-negative integer
	if lVal, exists := params["l"]; exists {
		l, err := strconv.ParseInt(lVal, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid body length 'l' value: %s", lVal)
		}
		if l < 0 {
			return fmt.Errorf("body length 'l' must be non-negative: %d", l)
		}
		// Prevent extremely large values that could cause memory issues
		if l > 1<<32 { // Limit to 4GB
			return fmt.Errorf("body length 'l' value too large: %d", l)
		}
	}

	return nil
}
