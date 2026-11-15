package dkim2

import (
	"bytes"
	"errors"
	"testing"
)

func explodedMessage(t *testing.T) ([]byte, Envelope, records) {
	t.Helper()
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}, "s2._domainkey.relay.test": {keyRecord(key)}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ForwardChecked(first, in, VerifyOptions{Resolver: resolver, Now: testTime}, SignOptions{
		Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime, Flags: []string{"exploded"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire, out, resolver
}

func TestExplodedDoesNotBypassReplayCheck(t *testing.T) {
	wire, envelope, resolver := explodedMessage(t)
	seen := make(map[string]bool)
	calls := 0
	options := VerifyOptions{Resolver: resolver, Now: testTime, ReplayCheck: func(id string) (bool, error) {
		calls++
		if id == "" {
			t.Fatal("missing replay ID")
		}
		duplicate := seen[id]
		seen[id] = true
		return duplicate, nil
	}}
	for i := 0; i < 2; i++ {
		result := Verify(wire, envelope, options)
		if result.Status != Pass || result.ReplayDetected != (i == 1) || result.ReplayErr != nil {
			t.Fatalf("delivery %d: %+v", i, result)
		}
		if len(result.ExplodedAt) != 1 || result.ExplodedAt[0] != (ExplodedHop{SignatureIndex: 2, Domain: "relay.test"}) {
			t.Fatalf("exploded claimant not authenticated: %+v", result.ExplodedAt)
		}
	}
	if calls != 2 {
		t.Fatalf("exploded mail bypassed replay store: calls=%d", calls)
	}
	tampered := bytes.Replace(wire, []byte("hello\r\n"), []byte("changed\r\n"), 1)
	result := Verify(tampered, envelope, options)
	if result.Status != Fail || result.ReplayID != "" || len(result.ExplodedAt) != 0 || calls != 2 {
		t.Fatalf("unauthenticated replay observation: %+v calls=%d", result, calls)
	}
}

func TestExplodedClaimantsWithoutReplayStore(t *testing.T) {
	wire, envelope, resolver := explodedMessage(t)
	key := edKey()
	out := Envelope{"<bounce@example.net>", []string{"<dave@destination.test>"}}
	forwarded, err := ForwardChecked(wire, envelope, VerifyOptions{Resolver: resolver, Now: testTime}, SignOptions{
		Domain: "example.net", Selector: "s3", Key: key, Envelope: out, Timestamp: testTime, Flags: []string{"exploded"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver["s3._domainkey.example.net"] = []string{keyRecord(key)}
	result := Verify(forwarded, out, VerifyOptions{Resolver: resolver, Now: testTime})
	if result.Status != Pass || len(result.ExplodedAt) != 2 || result.ExplodedAt[0].SignatureIndex != 2 || result.ExplodedAt[1] != (ExplodedHop{SignatureIndex: 3, Domain: "example.net"}) {
		t.Fatalf("missing exploded provenance: %+v", result)
	}
	storageErr := errors.New("storage unavailable")
	result = Verify(forwarded, out, VerifyOptions{Resolver: resolver, Now: testTime, ReplayCheck: func(string) (bool, error) {
		return false, storageErr
	}})
	if result.Status != Pass || !errors.Is(result.ReplayErr, storageErr) || len(result.ExplodedAt) != 2 {
		t.Fatalf("replay store failure was suppressed or changed authentication: %+v", result)
	}
}
