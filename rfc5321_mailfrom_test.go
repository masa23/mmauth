package mmauth

import (
	"net"
	"testing"

	"github.com/masa23/mmauth/spf"
)

func TestRFC5321QuotedPairMailFromPathUsesCorrectIdentity(t *testing.T) {
	const sender = `"a\"b"@example.com`
	gotSender, domain, err := parseMailFromIdentity("<" + sender + ">")
	if err != nil || gotSender != sender || domain != "example.com" {
		t.Fatalf("quoted pair path: sender=%q domain=%q error=%v", gotSender, domain, err)
	}
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	var queried []string
	spf.DefaultTXTResolver = func(name string) ([]string, error) {
		queried = append(queried, name)
		return []string{"v=spf1 +all"}, nil
	}
	result, spfDomain := evaluateSPFIdentity(net.ParseIP("192.0.2.1"), "helo.example.net", "<"+sender+">")
	if result.Status != spf.Pass || spfDomain != "example.com" || len(queried) != 1 || queried[0] != "example.com" {
		t.Fatalf("quoted pair SPF: status=%s domain=%q lookups=%v", result.Status, spfDomain, queried)
	}
}

func TestRFC5321QuotedLocalPartAllowsSpace(t *testing.T) {
	const sender = `"a b"@example.com`
	gotSender, domain, err := parseMailFromIdentity("<" + sender + ">")
	if err != nil || gotSender != sender || domain != "example.com" {
		t.Fatalf("quoted local part: sender=%q domain=%q error=%v", gotSender, domain, err)
	}
}

func TestRFC5321QuotedLocalPartAllowsAngleBrackets(t *testing.T) {
	const sender = `"a<b>"@example.com`
	gotSender, domain, err := parseMailFromIdentity("<" + sender + ">")
	if err != nil || gotSender != sender || domain != "example.com" {
		t.Fatalf("quoted local part: sender=%q domain=%q error=%v", gotSender, domain, err)
	}
}

func TestRFC5321SourceRouteUsesMailboxForSPF(t *testing.T) {
	const path = "<@relay.example,@next.example:user@example.com>"
	sender, domain, err := parseMailFromIdentity(path)
	if err != nil || sender != "user@example.com" || domain != "example.com" {
		t.Fatalf("source route: sender=%q domain=%q error=%v", sender, domain, err)
	}
	old := spf.DefaultTXTResolver
	t.Cleanup(func() { spf.DefaultTXTResolver = old })
	var queried []string
	spf.DefaultTXTResolver = func(name string) ([]string, error) {
		queried = append(queried, name)
		return []string{"v=spf1 +all"}, nil
	}
	result, spfDomain := evaluateSPFIdentity(net.ParseIP("192.0.2.1"), "helo.example.net", path)
	if result.Status != spf.Pass || spfDomain != "example.com" || len(queried) != 1 || queried[0] != "example.com" {
		t.Fatalf("source route SPF: status=%s domain=%q lookups=%v", result.Status, spfDomain, queried)
	}
}

func TestRFC7208QuotedLocalPartAtSignUsesCorrectSPFMacroDomain(t *testing.T) {
	oldTXT, oldIP := spf.DefaultTXTResolver, spf.DefaultIPResolver
	t.Cleanup(func() { spf.DefaultTXTResolver, spf.DefaultIPResolver = oldTXT, oldIP })
	var queried []string
	spf.DefaultTXTResolver = func(name string) ([]string, error) {
		queried = append(queried, "TXT "+name)
		return []string{"v=spf1 exists:%{o}.spf.example.net -all"}, nil
	}
	spf.DefaultIPResolver = func(name string) ([]net.IP, error) {
		queried = append(queried, "A "+name)
		if name == "example.com.spf.example.net" {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
		return nil, nil
	}
	result, domain := evaluateSPFIdentity(net.ParseIP("192.0.2.1"), "helo.example.net", `<"a@b"@example.com>`)
	if result.Status != spf.Pass || domain != "example.com" || len(queried) != 2 || queried[0] != "TXT example.com" || queried[1] != "A example.com.spf.example.net" {
		t.Fatalf("quoted local-part SPF: status=%s domain=%q lookups=%v", result.Status, domain, queried)
	}
}
