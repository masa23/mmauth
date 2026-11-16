package dkim2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A Recipe transforms the current message into its previous instance.
type recipe struct {
	Headers  map[string][]recipeStep
	Body     []recipeStep
	HasBody  bool
	NullBody bool
}

type recipeStep struct {
	Copy []int
	Data []string
}

func parseRecipe(encoded string) (recipe, error) {
	decoded, err := b64(encoded)
	if err != nil {
		return recipe{}, err
	}
	if !utf8.Valid(decoded) {
		return recipe{}, errors.New("dkim2: Recipe JSON is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber() // Preserve JSON's exact numeric values during key checks.
	if err := checkUniqueJSONValue(decoder); err != nil {
		return recipe{}, fmt.Errorf("dkim2: invalid Recipe JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return recipe{}, errors.New("dkim2: trailing Recipe JSON data")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &object); err != nil || object == nil {
		return recipe{}, errors.New("dkim2: invalid Recipe JSON object")
	}
	if _, ok := object["h"]; !ok {
		if _, ok := object["b"]; !ok {
			return recipe{}, errors.New("dkim2: Recipe has neither h nor b")
		}
	}
	r := recipe{}
	if raw, ok := object["h"]; ok {
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
			return recipe{}, errors.New("dkim2: invalid header Recipe")
		}
		r.Headers = make(map[string][]recipeStep)
		for name, value := range entries {
			if name != strings.ToLower(name) || !validFieldName(name) || unsigned(name) {
				return recipe{}, fmt.Errorf("dkim2: invalid Recipe header %q", name)
			}
			steps, err := parseSteps(value)
			if err != nil {
				return recipe{}, fmt.Errorf("dkim2: header Recipe %s: %w", name, err)
			}
			r.Headers[name] = steps
		}
	}
	if raw, ok := object["b"]; ok {
		r.HasBody = true
		if bytes.Equal(raw, []byte("null")) {
			r.NullBody = true
		} else {
			r.Body, err = parseSteps(raw)
			if err != nil {
				return recipe{}, fmt.Errorf("dkim2: body Recipe: %w", err)
			}
		}
	}
	return r, nil
}

// JSON maps silently discard duplicate keys; Recipes must reject them at
// every nesting level before decoding into maps.
func checkUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("non-string JSON key")
			}
			if key != strings.ToLower(key) {
				return fmt.Errorf("Recipe JSON key %q is not lower case", key)
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := checkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func parseSteps(raw json.RawMessage) ([]recipeStep, error) {
	var steps []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &steps); err != nil || steps == nil {
		return nil, errors.New("invalid Recipe step array")
	}
	var result []recipeStep
	previousEnd := 0
	for _, step := range steps {
		if len(step) != 1 {
			return nil, errors.New("Recipe step must have exactly one operation")
		}
		if data, ok := step["c"]; ok {
			var rawBounds []json.RawMessage
			if err := json.Unmarshal(data, &rawBounds); err != nil || len(rawBounds) != 2 {
				return nil, errors.New("invalid Recipe copy range")
			}
			first, firstOK := recipePositiveInteger(rawBounds[0])
			last, lastOK := recipePositiveInteger(rawBounds[1])
			if !firstOK || !lastOK || first <= previousEnd || first > last {
				return nil, errors.New("invalid Recipe copy range")
			}
			previousEnd = last
			result = append(result, recipeStep{Copy: []int{first, last}})
		} else if data, ok := step["d"]; ok {
			lines, ok := recipeStringArray(data)
			if !ok {
				return nil, errors.New("invalid Recipe data array")
			}
			for _, line := range lines {
				if strings.ContainsAny(line, "\r\n") {
					return nil, errors.New("CR or LF in Recipe data")
				}
			}
			result = append(result, recipeStep{Data: lines})
		} else if data, ok := step["u"]; ok {
			encoded, ok := recipeStringArray(data)
			if !ok {
				return nil, errors.New("invalid Recipe u array")
			}
			var lines []string
			for _, value := range encoded {
				// FWS is not allowed inside JSON u strings.
				decoded, err := b64(value)
				if err != nil || strings.ContainsAny(value, " \t\r\n") || bytes.ContainsAny(decoded, "\r\n") {
					return nil, errors.New("invalid Recipe u value")
				}
				lines = append(lines, string(decoded))
			}
			result = append(result, recipeStep{Data: lines})
		} else {
			return nil, errors.New("unknown Recipe step")
		}
	}
	return result, nil
}

// Decoding directly into []string silently treats JSON null as an empty
// string. Both d and u require a nonempty array containing only strings.
func recipeStringArray(raw json.RawMessage) ([]string, bool) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || len(values) == 0 {
		return nil, false
	}
	lines := make([]string, len(values))
	for i, value := range values {
		value = bytes.TrimSpace(value)
		if len(value) == 0 || value[0] != '"' {
			return nil, false
		}
		if err := json.Unmarshal(value, &lines[i]); err != nil {
			return nil, false
		}
	}
	return lines, true
}

// recipePositiveInteger implements JSON Schema integer semantics exactly.
// Decimal and exponent spellings are permitted, but fractions, zero, negative
// values and machine overflow are not. Work and allocation remain linear in
// the input; exponent magnitudes never cause unbounded zero expansion.
func recipePositiveInteger(raw json.RawMessage) (int, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
		return 0, false
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, false
	}
	mantissa := number.String()
	exponent := 0
	if index := strings.IndexAny(mantissa, "eE"); index >= 0 {
		var err error
		exponent, err = strconv.Atoi(mantissa[index+1:])
		if err != nil {
			return 0, false
		}
		mantissa = mantissa[:index]
	}
	fractionDigits := 0
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		fractionDigits = len(mantissa) - index - 1
		mantissa = mantissa[:index] + mantissa[index+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return 0, false
	}
	zeros := 0
	if exponent < fractionDigits {
		trailingZeros := len(digits) - len(strings.TrimRight(digits, "0"))
		// Compare before subtracting the exponent: an attacker may supply
		// the smallest int, whose negation would otherwise overflow.
		if exponent < fractionDigits-trailingZeros {
			return 0, false
		}
		digits = digits[:len(digits)-(fractionDigits-exponent)]
	} else {
		zeros = exponent - fractionDigits
	}
	maxDigits := len(strconv.Itoa(int(^uint(0) >> 1)))
	if len(digits) > maxDigits || zeros > maxDigits-len(digits) {
		return 0, false
	}
	value, err := strconv.Atoi(digits + strings.Repeat("0", zeros))
	return value, err == nil
}

func applyRecipe(m *Message, r recipe) (*Message, error) {
	previous := &Message{Headers: append([]string(nil), m.Headers...)}
	if !r.HasBody {
		previous.Body = append([]byte(nil), m.Body...)
	}
	for name, steps := range r.Headers {
		var originals []string // converted to bottom-to-top below
		var retained []string
		for _, field := range previous.Headers {
			fieldName, _, _ := strings.Cut(field, ":")
			if strings.EqualFold(fieldName, name) {
				originals = append(originals, field)
			} else {
				retained = append(retained, field)
			}
		}
		for left, right := 0, len(originals)-1; left < right; left, right = left+1, right-1 {
			originals[left], originals[right] = originals[right], originals[left]
		}
		var output []string // bottom to top
		outputBytes := 0
		for _, step := range steps {
			if step.Copy != nil {
				if step.Copy[1] > len(originals) {
					return nil, fmt.Errorf("dkim2: header Recipe %s copy exceeds available fields", name)
				}
				for _, field := range originals[step.Copy[0]-1 : step.Copy[1]] {
					output = append(output, field)
					outputBytes += len(field)
				}
			} else {
				for _, v := range step.Data {
					field := name + ":" + v + "\r\n"
					output = append(output, field)
					outputBytes += len(field)
				}
			}
			if outputBytes > 64<<20 {
				return nil, errors.New("dkim2: reconstructed headers exceed 64 MiB")
			}
			if len(output) > 100000 {
				return nil, errors.New("dkim2: reconstructed header count exceeds limit")
			}
		}
		for i := len(output) - 1; i >= 0; i-- {
			retained = append(retained, output[i])
		}
		previous.Headers = retained
	}
	if r.HasBody {
		if r.NullBody {
			return nil, errors.New("dkim2: null body Recipe cannot reconstruct the prior instance")
		}
		var out bytes.Buffer
		bodyOffset, bodyLine := 0, 0
		for _, step := range r.Body {
			if step.Copy != nil {
				// Copy ranges are ascending and non-overlapping. Scan only as
				// far as the requested end, without allocating an entry for
				// every line (a body may consist almost entirely of CRLFs).
				start := bodyOffset
				terminated := false
				for bodyLine < step.Copy[1] {
					if bodyOffset == len(m.Body) {
						return nil, errors.New("dkim2: body Recipe copy exceeds available lines")
					}
					if bodyLine == step.Copy[0]-1 {
						start = bodyOffset
					}
					end := bytes.Index(m.Body[bodyOffset:], []byte("\r\n"))
					terminated = end >= 0
					if terminated {
						bodyOffset += end + 2
					} else {
						bodyOffset = len(m.Body)
					}
					bodyLine++
				}
				needed := bodyOffset - start
				if !terminated {
					needed += 2
				}
				if needed > (64<<20)-out.Len() {
					return nil, errors.New("dkim2: reconstructed body exceeds 64 MiB")
				}
				out.Write(m.Body[start:bodyOffset])
				if !terminated {
					out.WriteString("\r\n")
				}
			} else {
				for _, line := range step.Data {
					if len(line) > (64<<20)-out.Len()-2 {
						return nil, errors.New("dkim2: reconstructed body exceeds 64 MiB")
					}
					out.WriteString(line)
					out.WriteString("\r\n")
				}
			}
		}
		previous.Body = out.Bytes()
	}
	return previous, nil
}
