package dkim

import (
	"fmt"
	"strings"
	"testing"
)

func TestRFC6376RequiredTagsAndIdentity(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA==\r\n"
	parsed, err := ParseSignature(base)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identity != "@example.com" {
		t.Fatalf("default identity=%q", parsed.Identity)
	}
	for _, tag := range []string{"v=1; ", "a=ed25519-sha256; ", "d=example.com; ", "s=s; ", "h=From; ", "bh=AA==; ", "b=AA=="} {
		t.Run("missing "+tag, func(t *testing.T) {
			if _, err := ParseSignature(strings.Replace(base, tag, "", 1)); err == nil {
				t.Fatalf("missing %q accepted", tag)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		change  string
		wantErr bool
	}{
		{"valid subdomain identity", "i=user@sub.example.com; ", false},
		{"case insensitive subdomain", "i=user@sub.Example.COM; ", false},
		{"identity without at sign", "i=user.example.com; ", true},
		{"identity without domain", "i=user@; ", true},
		{"empty identity", "i=; ", true},
		{"identity with empty label", "i=user@bad..example.com; ", true},
		{"unrelated identity", "i=user@other.com; ", true},
		{"suffix without dot", "i=user@badexample.com; ", true},
		{"unsigned From", "h=To; ", true},
		{"invalid version", "v=2; ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			if strings.HasPrefix(tc.change, "i=") {
				input = strings.Replace(input, "d=example.com; ", "d=example.com; "+tc.change, 1)
			} else if strings.HasPrefix(tc.change, "h=") {
				input = strings.Replace(input, "h=From; ", tc.change, 1)
			} else {
				input = strings.Replace(input, "v=1; ", tc.change, 1)
			}
			_, err := ParseSignature(input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, want error=%t", err, tc.wantErr)
			}
		})
	}
}

func TestRFC6376UnsignedDecimalSignatureTags(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA==; %s\r\n"
	for _, tag := range []string{"l=+1", "t=-1", "t=+1", "x=-1", "x=+1"} {
		t.Run(tag, func(t *testing.T) {
			if _, err := ParseSignature(fmt.Sprintf(base, tag)); err == nil {
				t.Fatalf("signed decimal tag %q accepted", tag)
			}
		})
	}
}

func TestRFC6376SignatureQueryMethods(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA==; q=%s\r\n"
	for _, tc := range []struct {
		method  string
		wantErr bool
	}{
		{"dns/txt", false},
		{"future:dns/txt", false},
		{"dns/txt:future", false},
		{"future : dns/txt", false},
		{"dns / txt", true},
		{"dns/t xt", true},
		{"dns/t xt:dns/txt", false},
		{"future/a=ZZ:dns/txt", true},
		{"future/a=20b:dns/txt", false},
		{"future", true},
		{"dns/other", true},
		{"", true},
	} {
		t.Run(tc.method, func(t *testing.T) {
			_, err := ParseSignature(fmt.Sprintf(base, tc.method))
			if (err != nil) != tc.wantErr {
				t.Fatalf("q=%q: error=%v, want error=%t", tc.method, err, tc.wantErr)
			}
		})
	}
	parsed, err := ParseSignature(fmt.Sprintf(base, "dns/txt"))
	if err != nil {
		t.Fatal(err)
	}
	parsed.QueryType = "future"
	resolver := &countTXTResolver{}
	parsed.VerifyWithResolver(nil, "", nil, resolver)
	if parsed.VerifyResult.Status() != VerifyStatusPermErr || resolver.calls != 0 {
		t.Fatalf("direct signature with unsupported q= returned %s after %d DNS calls", parsed.VerifyResult.Status(), resolver.calls)
	}
}

func TestRFC6376DomainSelectorAndSignedHeaderSyntax(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA==\r\n"
	for _, tc := range []struct {
		old, replacement string
		wantErr          bool
	}{
		{"d=example.com", "d=bad..example.com", true},
		{"d=example.com", "d=", true},
		{"d=example.com", "d=ex ample.com", true},
		{"d=example.com", "d=münchen.example", true},
		{"d=example.com", "d=EXAMPLE.com", false},
		{"s=s", "s=foo..bar", true},
		{"s=s", "s=foo_bar", true},
		{"s=s", "s=foo.bar", false},
		{"s=s", "s=", true},
		{"h=From", "h=From:", true},
		{"h=From", "h=Fr om", true},
		{"h=From", "h=From:Bad Name", true},
		{"h=From", "h=From:Subject", false},
		{"h=From", "h=From : Subject", false},
	} {
		t.Run(tc.replacement, func(t *testing.T) {
			_, err := ParseSignature(strings.Replace(base, tc.old, tc.replacement, 1))
			if (err != nil) != tc.wantErr {
				t.Fatalf("%s: error=%v, want error=%t", tc.replacement, err, tc.wantErr)
			}
		})
	}
}

func TestRFC6376SignatureRejectsTrailingControlCharacter(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA=="
	for _, suffix := range []string{"\v\r\n", "\f\r\n", "\n"} {
		if _, err := ParseSignature(base + suffix); err == nil {
			t.Errorf("accepted trailing control %q", suffix)
		}
	}
	if _, err := ParseSignature(base + "\r\n"); err != nil {
		t.Fatalf("valid terminal CRLF rejected: %v", err)
	}
}

func TestRFC6376ExplicitCanonicalizationRequiresKnownAlgorithm(t *testing.T) {
	const base = "DKIM-Signature: v=1; a=ed25519-sha256; d=example.com; s=s; h=From; bh=AA==; b=AA=="
	for _, value := range []string{"unknown", "simple/simple/relaxed", "relaxed /simple", ""} {
		if _, err := ParseSignature(base + "; c=" + value); err == nil {
			t.Errorf("invalid c=%q accepted", value)
		}
	}
	if _, err := ParseSignature(base + "; c=relaxed"); err != nil {
		t.Fatalf("valid single algorithm rejected: %v", err)
	}
}
