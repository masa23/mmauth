package spf

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

type spfZone struct {
	txt     map[string][]string
	txtErr  map[string]error
	ip      map[string][]net.IP
	ipErr   map[string]error
	mx      map[string][]*net.MX
	mxErr   map[string]error
	ptr     map[string][]string
	ptrErr  map[string]error
	queries []string
}

func newSPFZone() *spfZone {
	return &spfZone{txt: map[string][]string{}, txtErr: map[string]error{}, ip: map[string][]net.IP{}, ipErr: map[string]error{}, mx: map[string][]*net.MX{}, mxErr: map[string]error{}, ptr: map[string][]string{}, ptrErr: map[string]error{}}
}

func (z *spfZone) resolver() *dnsResolverImpl {
	d := newDNSResolver()
	d.txt = func(name string) ([]string, error) {
		z.queries = append(z.queries, "TXT "+name)
		return z.txt[name], z.txtErr[name]
	}
	d.ip = func(name string) ([]net.IP, error) {
		z.queries = append(z.queries, "IP "+name)
		return z.ip[name], z.ipErr[name]
	}
	d.mx = func(name string) ([]*net.MX, error) {
		z.queries = append(z.queries, "MX "+name)
		return z.mx[name], z.mxErr[name]
	}
	d.ptr = func(addr string) ([]string, error) {
		z.queries = append(z.queries, "PTR "+addr)
		return z.ptr[addr], z.ptrErr[addr]
	}
	return d
}

func (z *spfZone) check() (*Result, *dnsResolverImpl) {
	return z.checkIP("192.0.2.1")
}

func (z *spfZone) checkIP(addr string) (*Result, *dnsResolverImpl) {
	d := z.resolver()
	return d.CheckSPF(net.ParseIP(addr), "example.com", "a@example.com", "helo.example.com"), d
}

func assertSPF(t *testing.T, result *Result, want Status, queries, wantQueries []string) {
	t.Helper()
	if result.Status != want || !reflect.DeepEqual(queries, wantQueries) {
		t.Fatalf("status=%s, want %s; queries=%v, want %v; reason=%q", result.Status, want, queries, wantQueries, result.Reason)
	}
}

func TestRFC7208TXTSelectionAndConcatenation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []string
		want    Status
	}{
		{"one SPF and unrelated TXT", []string{"verification=ok", "v=spf1 +all"}, Pass},
		{"no TXT", nil, None},
		{"no SPF", []string{"verification=ok"}, None},
		{"two SPF", []string{"v=spf1 +all", "v=spf1 -all"}, PermError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = tc.records
			result, _ := z.check()
			assertSPF(t, result, tc.want, z.queries, []string{"TXT example.com"})
		})
	}
	// A TXT RR's strings are concatenated by the DNS adapter before SPF sees it.
	if got := concatTXTValue([]any{"v=spf1 ip4:192.0.2.", "1 -all"}); got != "v=spf1 ip4:192.0.2.1 -all" {
		t.Fatalf("TXT character-string concatenation=%q", got)
	}
	z := newSPFZone()
	z.txt["example.com"] = []string{concatTXTValue([]any{"v=spf1 ip4:192.0.2.", "1 -all"})}
	result, _ := z.check()
	assertSPF(t, result, Pass, z.queries, []string{"TXT example.com"})
}

func TestRFC7208MechanismOrderQualifiersAndUnknownModifier(t *testing.T) {
	for _, tc := range []struct {
		record string
		want   Status
	}{
		{"v=spf1 +all a:unused.example.com", Pass},
		{"v=spf1 -all a:unused.example.com", Fail},
		{"v=spf1 ~all a:unused.example.com", SoftFail},
		{"v=spf1 ?all a:unused.example.com", Neutral},
		{"v=spf1 ip4:192.0.2.1 -all x-future=ignored", Pass},
		{"v=spf1 ip4:192.0.2.2 -all x-future=ignored", Fail},
	} {
		t.Run(tc.record, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			result, _ := z.check()
			assertSPF(t, result, tc.want, z.queries, []string{"TXT example.com"})
		})
	}
}

func TestRFC7208ModifierMultiplicity(t *testing.T) {
	for _, tc := range []struct {
		record string
		want   Status
	}{
		{"v=spf1 +all redirect=one.example.com redirect=two.example.com", PermError},
		{"v=spf1 +all exp=one.example.com exp=two.example.com", PermError},
		{"v=spf1 +all x-future=one x-future=two", Pass},
	} {
		t.Run(tc.record, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			result, _ := z.check()
			assertSPF(t, result, tc.want, z.queries, []string{"TXT example.com"})
		})
	}
}

func TestRFC7208DNSPooledTermLimitAcrossInclude(t *testing.T) {
	for _, count := range []int{10, 11} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{"v=spf1 include:hop1.example.com -all"}
			for i := 1; i < count; i++ {
				z.txt[fmt.Sprintf("hop%d.example.com", i)] = []string{fmt.Sprintf("v=spf1 include:hop%d.example.com -all", i+1)}
			}
			z.txt[fmt.Sprintf("hop%d.example.com", count)] = []string{"v=spf1 +all"}
			result, resolver := z.check()
			want := Pass
			if count == 11 {
				want = PermError
			}
			if result.Status != want || resolver.termCounter != count {
				t.Fatalf("status=%s, terms=%d, want %s/%d", result.Status, resolver.termCounter, want, count)
			}
			var queries []string
			queries = append(queries, "TXT example.com")
			lastQuery := count
			if count == 11 {
				lastQuery = 10 // 11th term is rejected before querying DNS.
			}
			for i := 1; i <= lastQuery; i++ {
				queries = append(queries, fmt.Sprintf("TXT hop%d.example.com", i))
			}
			if !reflect.DeepEqual(z.queries, queries) {
				t.Fatalf("queries=%v, want %v", z.queries, queries)
			}
		})
	}
}

func TestRFC7208VoidLookupBoundary(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			z := newSPFZone()
			var terms []string
			wantQueries := []string{"TXT example.com"}
			for i := 1; i <= count; i++ {
				name := fmt.Sprintf("missing%d.example.com", i)
				terms = append(terms, "exists:"+name)
				wantQueries = append(wantQueries, "IP "+name)
				if i%2 == 0 {
					z.ipErr[name] = &net.DNSError{Name: name, IsNotFound: true}
				}
			}
			z.txt["example.com"] = []string{"v=spf1 " + strings.Join(terms, " ") + " -all"}
			result, resolver := z.check()
			want := Fail
			if count == 3 {
				want = PermError
			}
			assertSPF(t, result, want, z.queries, wantQueries)
			if resolver.voidCount != count {
				t.Fatalf("void count=%d, want %d", resolver.voidCount, count)
			}
		})
	}
}

func TestRFC7208IncludeResultsAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, record, child string
		childErr            error
		want                Status
		queries             []string
	}{
		{"include pass", "v=spf1 include:child.example.com -all", "v=spf1 +all", nil, Pass, []string{"TXT example.com", "TXT child.example.com"}},
		{"include fail then all", "v=spf1 include:child.example.com -all", "v=spf1 -all", nil, Fail, []string{"TXT example.com", "TXT child.example.com"}},
		{"include neutral then all", "v=spf1 include:child.example.com -all", "v=spf1 ?all", nil, Fail, []string{"TXT example.com", "TXT child.example.com"}},
		{"include softfail then all", "v=spf1 include:child.example.com -all", "v=spf1 ~all", nil, Fail, []string{"TXT example.com", "TXT child.example.com"}},
		{"include temp error", "v=spf1 include:child.example.com -all", "", errors.New("SERVFAIL"), TempError, []string{"TXT example.com", "TXT child.example.com"}},
		{"include no SPF", "v=spf1 include:child.example.com -all", "", nil, PermError, []string{"TXT example.com", "TXT child.example.com"}},
		{"redirect only", "v=spf1 redirect=child.example.com", "v=spf1 -all", nil, Fail, []string{"TXT example.com", "TXT child.example.com"}},
		{"all ignores redirect", "v=spf1 -all redirect=child.example.com", "v=spf1 +all", nil, Fail, []string{"TXT example.com"}},
		{"matched neutral ignores redirect", "v=spf1 ?all redirect=child.example.com", "v=spf1 +all", nil, Neutral, []string{"TXT example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSPFZone()
			z.txt["example.com"] = []string{tc.record}
			if tc.child != "" {
				z.txt["child.example.com"] = []string{tc.child}
			}
			z.txtErr["child.example.com"] = tc.childErr
			result, _ := z.check()
			assertSPF(t, result, tc.want, z.queries, tc.queries)
		})
	}
}
