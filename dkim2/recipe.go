package dkim2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
			var bounds []int
			if err := json.Unmarshal(data, &bounds); err != nil || len(bounds) != 2 || bounds[0] <= previousEnd || bounds[0] > bounds[1] {
				return nil, errors.New("invalid Recipe copy range")
			}
			previousEnd = bounds[1]
			result = append(result, recipeStep{Copy: bounds})
		} else if data, ok := step["d"]; ok {
			var lines []string
			if err := json.Unmarshal(data, &lines); err != nil || len(lines) == 0 {
				return nil, errors.New("invalid Recipe data array")
			}
			for _, line := range lines {
				if strings.ContainsAny(line, "\r\n") {
					return nil, errors.New("CR or LF in Recipe data")
				}
			}
			result = append(result, recipeStep{Data: lines})
		} else if data, ok := step["u"]; ok {
			var encoded []string
			if err := json.Unmarshal(data, &encoded); err != nil || len(encoded) == 0 {
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

func applyRecipe(m *Message, r recipe) (*Message, error) {
	previous := &Message{Headers: append([]string(nil), m.Headers...), Body: append([]byte(nil), m.Body...)}
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
		lines := splitBodyLines(previous.Body)
		var out bytes.Buffer
		for _, step := range r.Body {
			if step.Copy != nil {
				if step.Copy[1] > len(lines) {
					return nil, errors.New("dkim2: body Recipe copy exceeds available lines")
				}
				for _, line := range lines[step.Copy[0]-1 : step.Copy[1]] {
					out.WriteString(line)
					out.WriteString("\r\n")
				}
			} else {
				for _, line := range step.Data {
					out.WriteString(line)
					out.WriteString("\r\n")
				}
			}
			if out.Len() > 64<<20 {
				return nil, errors.New("dkim2: reconstructed body exceeds 64 MiB")
			}
		}
		previous.Body = out.Bytes()
	}
	return previous, nil
}

func splitBodyLines(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	parts := strings.Split(string(body), "\r\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
