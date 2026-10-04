package spf

import (
	"net"
	"strings"
	"testing"
)

func TestRegressionPTRBoundary(t *testing.T) {
	d := newDNSResolver()
	d.txt = func(string) ([]string, error) { return []string{"v=spf1 ptr:example.com -all"}, nil }
	d.ptr = func(string) ([]string, error) { return []string{"mail.bad-example.com."}, nil }
	d.ip = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.1")}, nil }
	got := d.CheckSPF(net.ParseIP("192.0.2.1"), "example.com", "a@example.com", "example.com")
	if got.Status != Fail {
		t.Errorf("unrelated PTR domain: got=%+v want fail", got)
	}
}

func TestRegressionExpPTRPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseRecord panicked: %v", r)
		}
	}()
	_, res := ParseRecord("v=spf1 -all exp=%{p}.example.com")
	if res != nil {
		t.Errorf("valid exp macro rejected: %+v", res)
	}
}

func TestRegressionExpBudget(t *testing.T) {
	d := newDNSResolver()
	d.txt = func(name string) ([]string, error) {
		if name == "example.com" {
			return []string{"v=spf1 " + strings.Repeat("a:other.example.com ", 10) + "-all exp=explain.example.com"}, nil
		}
		return []string{"denied"}, nil
	}
	d.ip = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.2")}, nil }
	got := d.CheckSPF(net.ParseIP("192.0.2.1"), "example.com", "a@example.com", "example.com")
	if got.Status != Fail || got.Reason != "denied" {
		t.Errorf("10 terms followed by exp: got=%+v want fail", got)
	}
}

func TestRegressionMacroTransformers(t *testing.T) {
	d := newDNSResolver()
	ip := net.ParseIP("192.0.2.1")
	d.ptr = func(string) ([]string, error) { return []string{"host.example.com."}, nil }
	d.ip = func(string) ([]net.IP, error) { return []net.IP{ip}, nil }
	ctx := MacroContext{IP: ip, Domain: "example.com", Sender: "x@example.com", DNSResolver: d}
	for _, tc := range []struct{ input, want string }{{"%{i2}", "2.1"}, {"%{P}", "host.example.com"}} {
		got, e := d.ReplaceMacroValues(tc.input, ctx, MacroPurposeDomainSpec)
		if e != nil || got != tc.want {
			t.Errorf("%s: got=%q err=%v want=%q", tc.input, got, e, tc.want)
		}
	}
}
