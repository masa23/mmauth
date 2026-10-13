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
