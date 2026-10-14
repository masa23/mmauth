package spf

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestRFC7208PublicCheckSPFErrorClassification(t *testing.T) {
	old := DefaultTXTResolver
	t.Cleanup(func() { DefaultTXTResolver = old })
	for _, tc := range []struct {
		name, domain, record string
		err                  error
		want                 Status
		queries              int
	}{
		{"invalid domain", "bad domain", "v=spf1 +all", nil, None, 0},
		{"no record", "example.com", "", nil, None, 1},
		{"temporary DNS failure", "example.com", "", errors.New("SERVFAIL"), TempError, 1},
		{"invalid SPF syntax", "example.com", "v=spf1 bad-mechanism", nil, PermError, 1},
		{"valid SPF", "example.com", "v=spf1 +all", nil, Pass, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			DefaultTXTResolver = func(string) ([]string, error) {
				queries++
				if tc.record == "" {
					return nil, tc.err
				}
				return []string{tc.record}, tc.err
			}
			got := CheckSPF(net.ParseIP("192.0.2.1"), tc.domain, "a@example.com", "helo.example.com")
			if got.Status != tc.want || queries != tc.queries {
				t.Fatalf("CheckSPF=%+v, queries=%d, want %s/%d", got, queries, tc.want, tc.queries)
			}
		})
	}
}

func TestRFC7208AAndMXFamiliesCIDRAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, record, addr string
		ips                []net.IP
		mxs                []*net.MX
		ipErr, mxErr       error
		want               Status
		queries            []string
	}{
		{"a IPv4 CIDR match", "v=spf1 a:host.example.com/24 -all", "192.0.2.1", []net.IP{net.ParseIP("192.0.2.99")}, nil, nil, nil, Pass, []string{"TXT example.com", "IP host.example.com"}},
		{"a IPv4 CIDR miss", "v=spf1 a:host.example.com/32 -all", "192.0.2.1", []net.IP{net.ParseIP("192.0.2.99")}, nil, nil, nil, Fail, []string{"TXT example.com", "IP host.example.com"}},
		{"a IPv6 CIDR match", "v=spf1 a:host.example.com//64 -all", "2001:db8::1", []net.IP{net.ParseIP("2001:db8::99")}, nil, nil, nil, Pass, []string{"TXT example.com", "IP host.example.com"}},
		{"a DNS error", "v=spf1 a:host.example.com -all", "192.0.2.1", nil, nil, errors.New("SERVFAIL"), nil, TempError, []string{"TXT example.com", "IP host.example.com"}},
		{"mx IPv4 CIDR match", "v=spf1 mx:mail.example.com/24 -all", "192.0.2.1", []net.IP{net.ParseIP("192.0.2.99")}, []*net.MX{{Host: "mx1.example.com"}}, nil, nil, Pass, []string{"TXT example.com", "MX mail.example.com", "IP mx1.example.com"}},
		{"mx IPv6 CIDR match", "v=spf1 mx:mail.example.com//64 -all", "2001:db8::1", []net.IP{net.ParseIP("2001:db8::99")}, []*net.MX{{Host: "mx1.example.com"}}, nil, nil, Pass, []string{"TXT example.com", "MX mail.example.com", "IP mx1.example.com"}},
		{"mx DNS error", "v=spf1 mx:mail.example.com -all", "192.0.2.1", nil, nil, nil, errors.New("SERVFAIL"), TempError, []string{"TXT example.com", "MX mail.example.com"}},
		{"mx host DNS error", "v=spf1 mx:mail.example.com -all", "192.0.2.1", nil, []*net.MX{{Host: "mx1.example.com"}}, errors.New("SERVFAIL"), nil, TempError, []string{"TXT example.com", "MX mail.example.com", "IP mx1.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			z.ip["host.example.com"], z.ip["mx1.example.com"] = tc.ips, tc.ips
			z.mx["mail.example.com"] = tc.mxs
			z.ipErr["host.example.com"], z.ipErr["mx1.example.com"] = tc.ipErr, tc.ipErr
			z.mxErr["mail.example.com"] = tc.mxErr
			result, _ := z.checkIP(tc.addr)
			assertSPF(t, result, tc.want, z.queries, tc.queries)
		})
	}
}

func TestRFC7208MXResourceLimits(t *testing.T) {
	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprintf("%d MX hosts", count), func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{"v=spf1 mx:mail.example.com -all"}
			wantQueries := []string{"TXT example.com", "MX mail.example.com"}
			for i := 1; i <= count; i++ {
				name := fmt.Sprintf("mx%d.example.com", i)
				z.mx["mail.example.com"] = append(z.mx["mail.example.com"], &net.MX{Host: name})
				z.ip[name] = []net.IP{net.ParseIP("192.0.2.2")}
				if count == 10 {
					wantQueries = append(wantQueries, "IP "+name)
				}
			}
			result, d := z.check()
			want := Fail
			if count == 11 {
				want = PermError
			}
			// Eleven hosts are rejected after the MX query, before any host lookup.
			if result.Status != want || d.termCounter != count || !reflect.DeepEqual(z.queries, wantQueries) {
				t.Fatalf("status=%s, terms=%d, queries=%v, want %s/%d/%v", result.Status, d.termCounter, z.queries, want, count, wantQueries)
			}
		})
	}
	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprintf("%d address records", count), func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{"v=spf1 mx:mail.example.com -all"}
			z.mx["mail.example.com"] = []*net.MX{{Host: "mx1.example.com"}}
			for i := 0; i < count; i++ {
				z.ip["mx1.example.com"] = append(z.ip["mx1.example.com"], net.ParseIP(fmt.Sprintf("192.0.2.%d", i+2)))
			}
			result, _ := z.check()
			want := Fail
			if count == 11 {
				want = PermError
			}
			assertSPF(t, result, want, z.queries, []string{"TXT example.com", "MX mail.example.com", "IP mx1.example.com"})
		})
	}
}

func TestRFC7208PTRReverseForwardAndCandidateLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []string
		ptrErr  error
		ip      map[string][]net.IP
		ipErr   map[string]error
		want    Status
		queries []string
	}{
		{"validated match", []string{"mx.example.com."}, nil, map[string][]net.IP{"mx.example.com": {net.ParseIP("192.0.2.1")}}, nil, Pass, []string{"TXT example.com", "PTR 192.0.2.1", "IP mx.example.com"}},
		{"forward mismatch", []string{"mx.example.com."}, nil, map[string][]net.IP{"mx.example.com": {net.ParseIP("192.0.2.2")}}, nil, Fail, []string{"TXT example.com", "PTR 192.0.2.1", "IP mx.example.com"}},
		{"reverse DNS error", nil, errors.New("SERVFAIL"), nil, nil, Fail, []string{"TXT example.com", "PTR 192.0.2.1"}},
		{"forward DNS error", []string{"mx.example.com."}, nil, nil, map[string]error{"mx.example.com": errors.New("SERVFAIL")}, Fail, []string{"TXT example.com", "PTR 192.0.2.1", "IP mx.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{"v=spf1 ptr:example.com -all"}
			z.ptr["192.0.2.1"], z.ptrErr["192.0.2.1"] = tc.targets, tc.ptrErr
			for k, v := range tc.ip {
				z.ip[k] = v
			}
			for k, v := range tc.ipErr {
				z.ipErr[k] = v
			}
			result, _ := z.check()
			assertSPF(t, result, tc.want, z.queries, tc.queries)
		})
	}

	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprintf("%d PTR candidates", count), func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{"v=spf1 ptr:example.com -all"}
			wantQueries := []string{"TXT example.com", "PTR 192.0.2.1"}
			for i := 1; i <= count; i++ {
				name := fmt.Sprintf("mx%d.example.com", i)
				z.ptr["192.0.2.1"] = append(z.ptr["192.0.2.1"], name+".")
				addr := "192.0.2.2"
				if i == count {
					addr = "192.0.2.1"
				}
				z.ip[name] = []net.IP{net.ParseIP(addr)}
				if i <= 10 {
					wantQueries = append(wantQueries, "IP "+name)
				}
			}
			result, d := z.check()
			want := Pass
			if count == 11 {
				want = Fail
			}
			assertSPF(t, result, want, z.queries, wantQueries)
			if d.termCounter != 10 {
				t.Fatalf("terms=%d, want 10", d.termCounter)
			}
		})
	}
}

func TestRFC7208IPFamilyCIDRAndExistsAOnly(t *testing.T) {
	for _, tc := range []struct {
		name, record, addr string
		ips                []net.IP
		want               Status
		queries            []string
	}{
		{"ip4 subnet match", "v=spf1 ip4:192.0.2.0/24 -all", "192.0.2.1", nil, Pass, []string{"TXT example.com"}},
		{"ip4 subnet miss", "v=spf1 ip4:192.0.2.0/25 -all", "192.0.2.200", nil, Fail, []string{"TXT example.com"}},
		{"ip6 subnet match", "v=spf1 ip6:2001:db8::/32 -all", "2001:db8::1", nil, Pass, []string{"TXT example.com"}},
		{"ip6 rejects mapped IPv4", "v=spf1 ip6:::ffff:192.0.2.0/120 -all", "::ffff:192.0.2.1", nil, Fail, []string{"TXT example.com"}},
		{"exists accepts A", "v=spf1 exists:host.example.com -all", "2001:db8::1", []net.IP{net.ParseIP("192.0.2.2")}, Pass, []string{"TXT example.com", "IP host.example.com"}},
		{"exists ignores AAAA", "v=spf1 exists:host.example.com -all", "2001:db8::1", []net.IP{net.ParseIP("2001:db8::2")}, Fail, []string{"TXT example.com", "IP host.example.com"}},
		{"exists forbids CIDR", "v=spf1 exists:host.example.com/24 -all", "192.0.2.1", nil, PermError, []string{"TXT example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			z.ip["host.example.com"] = tc.ips
			result, _ := z.checkIP(tc.addr)
			assertSPF(t, result, tc.want, z.queries, tc.queries)
		})
	}
}

func TestRFC7208ExplanationLookupAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name, record, exp string
		expErr            error
		wantStatus        Status
		wantReason        string
		wantQueries       []string
	}{
		{"failure explanation macro", "v=spf1 -all exp=explain.example.com", "Denied %{s}", nil, Fail, "Denied a@example.com", []string{"TXT example.com", "TXT explain.example.com"}},
		{"pass skips explanation", "v=spf1 +all exp=explain.example.com", "unused", nil, Pass, "matched all", []string{"TXT example.com"}},
		{"missing explanation", "v=spf1 -all exp=explain.example.com", "", nil, Fail, "DEFAULT", []string{"TXT example.com", "TXT explain.example.com"}},
		{"temporary DNS failure", "v=spf1 -all exp=explain.example.com", "", errors.New("SERVFAIL"), Fail, "DEFAULT", []string{"TXT example.com", "TXT explain.example.com"}},
		{"invalid explanation macro", "v=spf1 -all exp=explain.example.com", "Denied %{x}", nil, Fail, "DEFAULT", []string{"TXT example.com", "TXT explain.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			if tc.exp != "" {
				z.txt["explain.example.com"] = []string{tc.exp}
			}
			z.txtErr["explain.example.com"] = tc.expErr
			result, _ := z.check()
			assertSPF(t, result, tc.wantStatus, z.queries, tc.wantQueries)
			if result.Reason != tc.wantReason {
				t.Fatalf("reason=%q, want %q", result.Reason, tc.wantReason)
			}
		})
	}

	z := newSPFZone()
	z.txt["example.com"] = []string{"v=spf1 " + strings.Repeat("a:host.example.com ", 10) + "-all exp=explain.example.com"}
	z.ip["host.example.com"] = []net.IP{net.ParseIP("192.0.2.2")}
	z.txt["explain.example.com"] = []string{"Denied"}
	result, d := z.check()
	if result.Status != Fail || result.Reason != "Denied" || d.termCounter != 10 || len(z.queries) != 12 || z.queries[11] != "TXT explain.example.com" {
		t.Fatalf("ten terms plus exp: result=%+v terms=%d queries=%v", result, d.termCounter, z.queries)
	}
}

func TestRFC7208MacroFixedExpansionAndLength(t *testing.T) {
	d := newDNSResolver()
	ctx := MacroContext{IP: net.ParseIP("192.0.2.1"), Domain: "mail.example.com", Sender: "a+b@sub.example.com", Helo: "helo.example.com", DNSResolver: d}
	for _, tc := range []struct {
		input, want string
	}{
		{"%{d2}", "example.com"},
		{"%{dr}", "com.example.mail"},
		{"%{l1r+-}", "a"},
		{"%{l1+-}", "b"},
		{"%{S}", "a%2Bb%40sub.example.com"},
		{"%{h}", "helo.example.com"},
		{"%%_%_%-", "%_ %20"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := d.ReplaceMacroValues(tc.input, ctx, MacroPurposeExp)
			if err != nil || got != tc.want {
				t.Fatalf("macro=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
	ctx.Sender = `"a@b"@example.com`
	for _, tc := range []struct {
		input, want string
	}{
		{"%{l}", `"a@b"`},
		{"%{o}", "example.com"},
		{"%{s}", `"a@b"@example.com`},
	} {
		got, err := d.ReplaceMacroValues(tc.input, ctx, MacroPurposeExp)
		if err != nil || got != tc.want {
			t.Fatalf("quoted sender macro %s = %q, error=%v; want %q", tc.input, got, err, tc.want)
		}
	}
	long := strings.Repeat("a.", 130) + "example.com"
	got, res := expandDomainSpec(long, ctx, MacroPurposeDomainSpec)
	if res != nil || len(got) > 253 || !strings.HasSuffix(got, ".example.com") || strings.HasPrefix(got, strings.Repeat("a.", 130)) {
		t.Fatalf("long domain expansion=%q, result=%+v", got, res)
	}
}

func TestRFC7208RedirectNoExtraLookup(t *testing.T) {
	z := newSPFZone()
	z.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.2 redirect=child.example.com"}
	z.txt["child.example.com"] = []string{"v=spf1 +all"}
	result, d := z.check()
	assertSPF(t, result, Pass, z.queries, []string{"TXT example.com", "TXT child.example.com"})
	if d.termCounter != 1 {
		t.Fatalf("redirect terms=%d, want 1", d.termCounter)
	}
	z = newSPFZone()
	z.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.1 redirect=child.example.com"}
	result, d = z.check()
	assertSPF(t, result, Pass, z.queries, []string{"TXT example.com"})
	if d.termCounter != 0 {
		t.Fatalf("matched mechanism consumed redirect term: %d", d.termCounter)
	}
}
