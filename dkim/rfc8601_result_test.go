package dkim

import (
	"strings"
	"testing"
)

func TestRFC8601DKIMResultStatusAndHeaderProperties(t *testing.T) {
	for _, tc := range []struct {
		status VerifyStatus
		want   string
	}{
		{VerifyStatusNone, "dkim=none"},
		{VerifyStatusNeutral, "dkim=neutral header.d=example.com header.s=selector header.i=a@example.com"},
		{VerifyStatusPass, "dkim=pass header.d=example.com header.s=selector header.i=a@example.com"},
		{VerifyStatusFail, "dkim=fail header.d=example.com header.s=selector header.i=a@example.com"},
		{VerifyStatusTempErr, "dkim=temperror header.d=example.com header.s=selector header.i=a@example.com"},
		{VerifyStatusPermErr, "dkim=permerror header.d=example.com header.s=selector header.i=a@example.com"},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			d := &Signature{Domain: "example.com", Selector: "selector", Identity: "a@example.com", VerifyResult: &VerifyResult{status: tc.status}}
			if got := d.ResultString(); got != tc.want {
				t.Fatalf("ResultString()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestRFC8601DKIMResultSpecialCharacters(t *testing.T) {
	d := &Signature{
		Domain:   "example.com; spf=pass",
		Selector: "bad\r\nInjected: yes",
		Identity: "a@example.com; arc=pass",
		VerifyResult: &VerifyResult{
			status: VerifyStatusFail,
			msg:    "bad ) ; spf=pass\r\nInjected: \"yes\" \\ path",
		},
	}
	got := d.ResultString()
	if got != `dkim=fail reason="bad ) ; spf=pass Injected: \"yes\" \\ path"` {
		t.Fatalf("special result=%q", got)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("result contains a line break: %q", got)
	}
	d = &Signature{Identity: `"a b"@example.com`, VerifyResult: &VerifyResult{status: VerifyStatusPass}}
	if got := d.ResultString(); got != `dkim=pass header.i="a b"@example.com` {
		t.Fatalf("quoted identity=%q", got)
	}
}

func TestRFC8601DKIMResultDomainAndSelectorSyntax(t *testing.T) {
	d := &Signature{Domain: "bad..example", Selector: "-invalid", VerifyResult: &VerifyResult{status: VerifyStatusPass}}
	if got := d.ResultString(); got != "dkim=pass" {
		t.Fatalf("invalid domain or selector emitted: %q", got)
	}
	d.Domain, d.Selector = "münchen.example", "selector.v1"
	if got := d.ResultString(); got != "dkim=pass header.d=münchen.example header.s=selector.v1" {
		t.Fatalf("valid internationalized domain and selector lost: %q", got)
	}
}
