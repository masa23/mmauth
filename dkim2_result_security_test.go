package mmauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/masa23/mmauth/dkim2"
)

func dkim2ExplodedVerification(t *testing.T) *MMAuth {
	t.Helper()
	wire, incoming, resolver, when := dkim2TestMessage(t)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<carol@example.net>"}}
	resolver.records["s2._domainkey.relay.test"] = []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	wire, err := dkim2.ForwardChecked(wire, incoming, dkim2.VerifyOptions{Resolver: resolver, Now: when}, dkim2.SignOptions{
		Domain: "relay.test", Selector: "s2", Key: key, Envelope: outgoing, Timestamp: when, Flags: []string{"exploded"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMMAuthWithOptions(MMAuthOptions{EnableDKIM2: true, DKIM2Envelope: outgoing,
		DKIM2VerifyOptions: dkim2.VerifyOptions{Resolver: resolver, Now: when}})
	if err != nil {
		t.Fatal(err)
	}
	writeAndVerify(t, m, wire)
	got := m.GetDKIM2Verification()
	if !got.Checked || got.Result.Status != dkim2.Pass || len(got.Result.ExplodedAt) != 1 {
		t.Fatalf("exploded message not authenticated: %+v", got)
	}
	return m
}

func TestDKIM2VerificationExplodedAtIsIndependent(t *testing.T) {
	m := dkim2ExplodedVerification(t)
	first := m.GetDKIM2Verification()
	first.Result.ExplodedAt[0].Domain = "modified.invalid"
	first.Result.ExplodedAt[0].SignatureIndex = 99
	second := m.GetDKIM2Verification()
	if second.Result.ExplodedAt[0] != (dkim2.ExplodedHop{SignatureIndex: 2, Domain: "relay.test"}) {
		t.Fatalf("caller mutated internal verification result: %+v", second.Result.ExplodedAt)
	}
}

func TestDKIM2VerificationConcurrentResultEditsAreIndependent(t *testing.T) {
	m := dkim2ExplodedVerification(t)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				result := m.GetDKIM2Verification()
				if result.Result.ExplodedAt[0] != (dkim2.ExplodedHop{SignatureIndex: 2, Domain: "relay.test"}) {
					t.Error("another caller's edits changed the authenticated result")
					return
				}
				result.Result.ExplodedAt[0].SignatureIndex = index
				result.Result.ExplodedAt[0].Domain = "modified.invalid"
			}
		}(i)
	}
	workers.Wait()
}
