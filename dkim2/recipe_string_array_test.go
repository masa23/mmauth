package dkim2

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Draft-09 section 5 requires every d/u item to be a JSON string. In
// particular, null is not the valid empty string, even inside mixed arrays.
func TestRecipeDataArraysRequireStrings(t *testing.T) {
	for _, target := range []string{"body", "header"} {
		for _, operation := range []string{"d", "u"} {
			for _, items := range []string{
				`[null]`, `["",null]`, `[null,""]`, `[null,null]`,
				`[true]`, `[false]`, `[0]`, `[1.0]`, `[{}]`, `[[]]`,
				`["",0]`, `[]`, `null`, `""`, `{}`, `true`,
			} {
				t.Run(target+"/"+operation+"/"+items, func(t *testing.T) {
					step := fmt.Sprintf(`[{%q:%s}]`, operation, items)
					input := `{"b":` + step + `}`
					if target == "header" {
						input = `{"h":{"subject":` + step + `}}`
					}
					if _, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(input))); err == nil {
						t.Fatalf("non-string or empty data array accepted: %s", input)
					}
				})
			}
		}
	}
}

func TestRecipeDataArraysPreserveStringValues(t *testing.T) {
	for _, test := range []struct {
		name, data, want string
	}{
		{"empty d", `{"d":[""]}`, "\r\n"},
		{"empty u", `{"u":[""]}`, "\r\n"},
		{"UTF-8 d", `{"d":["日本語"]}`, "日本語\r\n"},
		{"escaped d", `{"d":["\u65e5\u672c\u8a9e"]}`, "日本語\r\n"},
		{"binary u", `{"u":["/w=="]}`, "\xff\r\n"},
		{"mixed strings", `{"d":["","x",""]}`, "\r\nx\r\n\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `{"b":[` + test.data + `],"h":{"subject":[` + test.data + `]}}`
			r, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(input)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := applyRecipe(&Message{}, r)
			if err != nil || string(got.Body) != test.want {
				t.Fatalf("body=%q want=%q err=%v", got.Body, test.want, err)
			}
			var headerValues string
			for i := len(got.Headers) - 1; i >= 0; i-- {
				headerValues += strings.TrimPrefix(got.Headers[i], "subject:")
			}
			if headerValues != test.want {
				t.Fatalf("header values=%q want=%q", headerValues, test.want)
			}
		})
	}
	if r, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(`{"b":null}`))); err != nil || !r.NullBody {
		t.Fatalf("explicit null body Recipe changed: %+v %v", r, err)
	}
}

// Sign a second instance independently of ReviseChecked so malformed Recipes
// reach Verify after successful cryptographic and current-instance checks.
func TestRecipeNullItemsRejectedBySigningAndVerification(t *testing.T) {
	key := edKey()
	incoming := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	outgoing := Envelope{"<bounce@relay.test>", []string{"<carol@destination.test>"}}
	verification := VerifyOptions{Resolver: records{
		"s1._domainkey.example.com": {keyRecord(key)},
		"s2._domainkey.relay.test":  {keyRecord(key)},
	}, Now: testTime}
	first, err := Sign([]byte("From: alice@example.com\r\nSubject:\r\n\r\n\r\n"), SignOptions{
		Domain: "example.com", Selector: "s1", Key: key, Envelope: incoming, Timestamp: testTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	h := parsed.Instances[0].Hashes[0]
	options := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: outgoing, Timestamp: testTime}
	for _, target := range []string{"body", "header"} {
		for _, operation := range []string{"d", "u"} {
			for _, value := range []string{`null`, `""`} {
				t.Run(target+"/"+operation+"/"+value, func(t *testing.T) {
					step := fmt.Sprintf(`[{%q:[%s]}]`, operation, value)
					input := `{"b":` + step + `}`
					if target == "header" {
						input = `{"h":{"subject":` + step + `}}`
					}
					_, err := ReviseChecked(first, first, incoming, verification, []byte(input), options)
					if value == `null` && (err == nil || !strings.Contains(err.Error(), "invalid Recipe")) {
						t.Fatalf("ReviseChecked accepted null item or returned unrelated error: %v", err)
					}
					if value == `""` && err != nil {
						t.Fatalf("ReviseChecked rejected valid empty string: %v", err)
					}
					encoded := base64.StdEncoding.EncodeToString([]byte(input))
					mi := fmt.Sprintf("Message-Instance: m=2; r=%s; h=%s:%s:%s;\r\n", encoded, h.Algorithm, h.Header, h.Body)
					instances := append(append([]Instance(nil), parsed.Instances...), Instance{Number: 2, Raw: mi})
					sig, err := makeSignature(instances, parsed.Signatures, 2, options)
					if err != nil {
						t.Fatal(err)
					}
					wire := append([]byte(sig+mi), first...)
					result := Verify(wire, outgoing, verification)
					if value == `null` && (result.Status != PermError || result.Err == nil || !strings.Contains(result.Err.Error(), "invalid Recipe")) {
						t.Fatalf("Verify accepted null item or failed elsewhere: %+v", result)
					}
					if value == `""` && result.Status != Pass {
						t.Fatalf("Verify rejected valid empty string: %+v", result)
					}
				})
			}
		}
	}
}
