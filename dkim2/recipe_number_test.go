package dkim2

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestRecipeCopyJSONIntegerValues applies the draft-09 schema's mathematical
// integer semantics without permitting rounded fractions or machine overflow.
func TestRecipeCopyJSONIntegerValues(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	maximum := strconv.Itoa(maxInt)
	valid := []struct {
		number string
		want   int
	}{
		{"1", 1},
		{"1.0", 1},
		{"1e0", 1},
		{"1E+0000", 1},
		{"1e-0", 1},
		{"0.1e1", 1},
		{"10e-1", 1},
		{"1000.0000e-3", 1},
		{"1.23e2", 123},
		{"123.0e+1", 1230},
		{maximum, maxInt},
		{maximum + ".0000", maxInt},
		{maximum + "0e-1", maxInt},
		{"1" + strings.Repeat("0", 500) + "e-500", 1},
		{"0." + strings.Repeat("0", 500) + "1e501", 1},
		{"1e+" + strings.Repeat("0", 1024), 1},
		{"0.01e" + strings.Repeat("0", 1024) + "2", 1},
	}
	if strconv.IntSize == 64 {
		large := int64(9007199254740993)
		valid = append(valid, struct {
			number string
			want   int
		}{"9007199254740993.0", int(large)})
	}
	for index, test := range valid {
		t.Run(fmt.Sprintf("valid-%d", index), func(t *testing.T) {
			input := fmt.Sprintf(`{"h":{"subject":[{"c":[%s,%s]}]},"b":[{"c":[%s,%s]}]}`, test.number, test.number, test.number, test.number)
			got, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(input)))
			if err != nil {
				t.Fatalf("valid integer %q: %v", test.number, err)
			}
			for _, steps := range [][]recipeStep{got.Headers["subject"], got.Body} {
				if len(steps) != 1 || len(steps[0].Copy) != 2 || steps[0].Copy[0] != test.want || steps[0].Copy[1] != test.want {
					t.Fatalf("integer %q changed value: %+v", test.number, steps)
				}
			}
		})
	}

	invalid := []string{
		"0", "0.0", "0e99999999999999999999", "-0", "-1", "-1.0", "-1e0",
		"1.1", "1.000000000000000000000000000000000001", "1e-1", "12e-1",
		"0.99999999999999999999999999999999999999999999999999999999999999",
		strconv.FormatUint(uint64(maxInt)+1, 10),
		strconv.FormatUint(uint64(maxInt)+1, 10) + ".0",
		maximum + ".000000000000000000000000000001",
		"1e" + maximum,
		"1e" + strconv.Itoa(-maxInt-1),
		"1.0e" + strconv.Itoa(-maxInt-1),
		"1e99999999999999999999999999999999999999",
		"1e-99999999999999999999999999999999999999",
		"1e" + strings.Repeat("9", 4096),
		"1e-" + strings.Repeat("9", 4096),
		"null", "true", "false", `"1"`, `"1e0"`, "{}", "[]",
	}
	for index, number := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			input := fmt.Sprintf(`{"b":[{"c":[%s,%s]}]}`, number, number)
			if _, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(input))); err == nil {
				t.Fatalf("invalid integer %q accepted", number)
			}
		})
	}
}

// TestRecipeIntegerSyntaxPreservesCopyRangeRules keeps the independent range
// ordering and duplicate-key requirements in force for every number spelling.
func TestRecipeIntegerSyntaxPreservesCopyRangeRules(t *testing.T) {
	for _, input := range []string{
		`{"b":[{"c":[2.0,1e0]}]}`,
		`{"b":[{"c":[1.0,2e0]},{"c":[2.0,3e0]}]}`,
		`{"b":[{"c":[1e0]}]}`,
		`{"b":[{"c":[1e0,1.0,1]}]}`,
		`{"b":[{"c":null}]}`,
		`{"b":[{"c":[1e0,1.0],"c":[1,1]}]}`,
	} {
		if _, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(input))); err == nil {
			t.Fatalf("invalid copy range accepted: %s", input)
		}
	}
}

// TestRecipeIntegerSpellingsAuthenticate verifies that decimal and exponent
// copy bounds survive signing and complete historical reconstruction.
func TestRecipeIntegerSpellingsAuthenticate(t *testing.T) {
	key := edKey()
	incoming := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	outgoing := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
	resolver := records{
		"s1._domainkey.example.com": {keyRecord(key)},
		"s2._domainkey.relay.test":  {keyRecord(key)},
	}
	verification := VerifyOptions{Resolver: resolver, Now: testTime}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: incoming, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{"1", "1.0", "1e0", "0.1e1", "10e-1"} {
		t.Run(number, func(t *testing.T) {
			recipe := []byte(fmt.Sprintf(`{"h":{"subject":[{"c":[%s,%s]}]},"b":[{"c":[%s,%s]}]}`, number, number, number, number))
			revised, err := ReviseChecked(wire, wire, incoming, verification, recipe, SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: outgoing, Timestamp: testTime})
			if err != nil {
				t.Fatalf("valid Recipe rejected: %v", err)
			}
			if result := Verify(revised, outgoing, verification); result.Status != Pass {
				t.Fatalf("Recipe failed historical verification: %+v", result)
			}
		})
	}
}
