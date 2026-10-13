package arc

import (
	"reflect"
	"strings"
	"testing"
)

func TestRFC8601AARQuotedFoldedAndNestedComments(t *testing.T) {
	const raw = "ARC-Authentication-Results: i=3 (relay); mx.example.net (outer (nested; note));\r\n" +
		" dkim=pass reason=\"verified; with \\\"quote\\\"\" header.i=\"a;b\"@example.net;\r\n" +
		" spf=fail smtp.mailfrom=\"x;y\"@example.org; arc=pass\r\n"
	aar, err := ParseARCAuthenticationResults(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`dkim=pass reason="verified; with \"quote\"" header.i="a;b"@example.net`,
		`spf=fail smtp.mailfrom="x;y"@example.org`,
		"arc=pass",
	}
	if aar.InstanceNumber != 3 || aar.AuthServId != "mx.example.net" || !reflect.DeepEqual(aar.Results, want) || aar.Raw() != raw {
		t.Fatalf("parsed AAR=%+v, want results=%q", aar, want)
	}
	encoded := (ARCAuthenticationResults{InstanceNumber: aar.InstanceNumber, AuthServId: aar.AuthServId, Results: aar.Results}).String()
	parsed, err := ParseARCAuthenticationResults("ARC-Authentication-Results: " + encoded + "\r\n")
	if err != nil || !reflect.DeepEqual(parsed.Results, want) {
		t.Fatalf("round trip=%+v, error=%v", parsed, err)
	}
}

func TestRFC8601AARFormatterRejectsInvalidFields(t *testing.T) {
	valid := ARCAuthenticationResults{InstanceNumber: 1, AuthServId: "mx.example.net", Results: []string{"dkim=pass"}}
	formatted, err := valid.Format()
	if err != nil || formatted != "i=1; mx.example.net; dkim=pass" || valid.String() != formatted {
		t.Fatalf("valid AAR: value=%q error=%v", formatted, err)
	}
	for _, tc := range []struct {
		name string
		aar  ARCAuthenticationResults
	}{
		{"zero instance", ARCAuthenticationResults{InstanceNumber: 0, AuthServId: "mx.example.net"}},
		{"too many instances", ARCAuthenticationResults{InstanceNumber: 51, AuthServId: "mx.example.net"}},
		{"authserv-id header injection", ARCAuthenticationResults{InstanceNumber: 1, AuthServId: "mx.example.net\r\nInjected: yes"}},
		{"result header injection", ARCAuthenticationResults{InstanceNumber: 1, AuthServId: "mx.example.net", Results: []string{"dkim=pass\r\nInjected: yes"}}},
		{"mixed none and result", ARCAuthenticationResults{InstanceNumber: 1, AuthServId: "mx.example.net", Results: []string{"none", "dkim=pass"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if value, err := tc.aar.Format(); err == nil || value != "" {
				t.Fatalf("invalid AAR formatted: value=%q error=%v", value, err)
			}
			if value := tc.aar.String(); value != "" {
				t.Fatalf("invalid AAR serialized: %q", value)
			}
		})
	}
}

func TestRFC8601AARInstanceCommentEscapes(t *testing.T) {
	const raw = "ARC-Authentication-Results: i=1 (edge \\); relay); mx.example.net; none\r\n"
	aar, err := ParseARCAuthenticationResults(raw)
	if err != nil || aar.InstanceNumber != 1 || aar.Raw() != raw {
		t.Fatalf("escaped instance comment: AAR=%+v, error=%v", aar, err)
	}
}

func TestRFC8601AARRejectsBrokenFieldStructure(t *testing.T) {
	for _, raw := range []string{
		" ARC-Authentication-Results: i=1; mx.example.net; none\r\n",
		"ARC-Authentication-Results : i=1; mx.example.net; none\r\n",
		"ARC-Authentication-Results: i=1;; dkim=pass\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass\r\nInjected: yes\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass\nspf=pass\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass\x01\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; none\v\r\n",
		"ARC-Authentication-Results: i=1 \x01; mx.example.net; none\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; none; dkim=pass\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; garbage\r\n",
		"ARC-Authentication-Results: i=1; bad=authserv; dkim=pass\r\n",
		"ARC-Authentication-Results: i=0; mx.example.net; dkim=pass\r\n",
		"ARC-Authentication-Results: i=0001; mx.example.net; dkim=pass\r\n",
		"ARC-Authentication-Results: i=+1; mx.example.net; dkim=pass\r\n",
		"ARC-Authentication-Results: I=1; mx.example.net; dkim=pass\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass garbage\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass reason=\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass header.d=\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass reason=ok reason=again\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass header.d=example.net reason=late\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim=pass header.d=bad=value\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; dkim-=pass\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; spf=pass smtp.mailfrom=a..b@example.net\r\n",
		"ARC-Authentication-Results: i=1; mx.example.net; spf=pass smtp.mailfrom=.a@example.net\r\n",
	} {
		t.Run(strings.TrimSpace(raw), func(t *testing.T) {
			if _, err := ParseARCAuthenticationResults(raw); err == nil {
				t.Fatalf("malformed AAR accepted: %q", raw)
			}
		})
	}
}

func TestRFC8601AARQuotedAuthservIDAndMethodVersion(t *testing.T) {
	const raw = "ARC-Authentication-Results: i=1; \"edge; relay\" 1; dkim/1=pass header.d=example.net\r\n"
	aar, err := ParseARCAuthenticationResults(raw)
	if err != nil || aar.AuthServId != `"edge; relay" 1` || !reflect.DeepEqual(aar.Results, []string{"dkim/1=pass header.d=example.net"}) {
		t.Fatalf("AAR=%+v, error=%v", aar, err)
	}
}

func TestRFC8601AARInternationalizedIdentity(t *testing.T) {
	const raw = "ARC-Authentication-Results: i=1; münchen.example; spf=pass smtp.mailfrom=δοκιμή@παράδειγμα.δοκιμή; spf=pass smtp.mailfrom=a=b@example.net\r\n"
	aar, err := ParseARCAuthenticationResults(raw)
	if err != nil || aar.AuthServId != "münchen.example" || !reflect.DeepEqual(aar.Results, []string{"spf=pass smtp.mailfrom=δοκιμή@παράδειγμα.δοκιμή", "spf=pass smtp.mailfrom=a=b@example.net"}) {
		t.Fatalf("internationalized AAR=%+v, error=%v", aar, err)
	}
}
