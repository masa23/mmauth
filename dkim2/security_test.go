package dkim2

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type countingMissingResolver struct{ calls int }

func (r *countingMissingResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.calls++
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

type waitForContextResolver struct{}

func (waitForContextResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestVerificationLimitsDNSLookupsAcrossSelectors(t *testing.T) {
	hash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signature := base64.StdEncoding.EncodeToString(make([]byte, 64))
	sets := make([]string, 1000)
	for i := range sets {
		sets[i] = fmt.Sprintf("s%d:ed25519-sha256:%s", i, signature)
	}
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire := fmt.Sprintf("DKIM2-Signature: i=1; m=1; t=%d; mf=%s; rt=%s; d=example.com; s=%s;\r\nMessage-Instance: m=1; h=sha256:%s:%s;\r\nFrom: alice@example.com\r\n\r\nbody\r\n",
		testTime.Unix(), base64.StdEncoding.EncodeToString([]byte(env.MailFrom)), base64.StdEncoding.EncodeToString([]byte(env.RcptTo[0])), strings.Join(sets, ","), hash, hash)
	resolver := &countingMissingResolver{}
	result := Verify([]byte(wire), env, VerifyOptions{Resolver: resolver, Now: testTime})
	if result.Status != PermError || result.Err == nil || !strings.Contains(result.Err.Error(), "DNS lookup limit") {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	if resolver.calls != maxVerificationDNSLookups {
		t.Fatalf("DNS calls=%d, want %d", resolver.calls, maxVerificationDNSLookups)
	}
	configured := &countingMissingResolver{}
	result = Verify([]byte(wire), env, VerifyOptions{Resolver: configured, Now: testTime, MaxDNSLookups: 40})
	if result.Status != PermError || configured.calls != 40 {
		t.Fatalf("configured DNS budget: status=%s calls=%d err=%v", result.Status, configured.calls, result.Err)
	}
}

func TestVerificationAppliesTotalDNSDeadline(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result := Verify(wire, env, VerifyOptions{Resolver: waitForContextResolver{}, Now: testTime, DNSBudget: 20 * time.Millisecond})
	if result.Status != TempError || time.Since(start) > time.Second {
		t.Fatalf("DNS deadline: status=%s elapsed=%s err=%v", result.Status, time.Since(start), result.Err)
	}
}

func TestVerificationRejectsShortRSAPublicKey(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 511)
	n.Add(n, big.NewInt(3))
	pub := &rsa.PublicKey{N: n, E: 65537}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	_, err := lookupKey(records{"s1._domainkey.example.com": {record}}, "example.com", "s1", "rsa-sha256")
	var permanent *permanentKeyError
	if err == nil || !strings.Contains(err.Error(), "shorter than 1024") || !errors.As(err, &permanent) {
		t.Fatalf("weak RSA key error=%v", err)
	}
}

func TestVerificationRejectsWrongRSAPublicExponent(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 1023)
	n.Add(n, big.NewInt(3))
	pub := &rsa.PublicKey{N: n, E: 3}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(pub))
	_, err := lookupKey(records{"s1._domainkey.example.com": {record}}, "example.com", "s1", "rsa-sha256")
	var permanent *permanentKeyError
	if err == nil || !strings.Contains(err.Error(), "exponent") || !errors.As(err, &permanent) {
		t.Fatalf("invalid RSA exponent error=%v", err)
	}
}

func TestAdditionalSigningRequiresCheckedOrOutOfBandPath(t *testing.T) {
	key := edKey()
	in := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	out := Envelope{"<bounce@relay.test>", []string{"<carol@example.net>"}}
	first, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: in, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	options := SignOptions{Domain: "relay.test", Selector: "s2", Key: key, Envelope: out, Timestamp: testTime}
	if _, err := Forward(first, options); err == nil {
		t.Fatal("Forward signed without authentication or out-of-band arrangement")
	}
	modified := bytes.Replace(first, []byte("Subject: original"), []byte("Subject: revised"), 1)
	recipe := []byte(`{"h":{"subject":[{"d":[" original"]}]}}`)
	if _, err := Revise(modified, recipe, options); err == nil {
		t.Fatal("Revise signed without authentication or out-of-band arrangement")
	}
	options.OutOfBandArrangement = true
	if _, err := Forward(first, options); err != nil {
		t.Fatalf("out-of-band Forward: %v", err)
	}
	if _, err := Revise(modified, recipe, options); err != nil {
		t.Fatalf("out-of-band Revise: %v", err)
	}
}
