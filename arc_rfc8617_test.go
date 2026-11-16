package mmauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/domainkey"
)

const arcEmptyBodyHash = "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="

var arcTestWhitespace = regexp.MustCompile(`[ \t]+`)

// These fixtures use the standard crypto implementation and an independent
// one-line header canonicalizer, without calling the ARC signing code.
func arcTestRelaxedHeader(field string) string {
	name, value, _ := strings.Cut(strings.TrimSuffix(field, "\r\n"), ":")
	return strings.ToLower(name) + ":" + arcTestWhitespace.ReplaceAllString(strings.TrimSpace(value), " ") + "\r\n"
}

func arcTestSign(key ed25519.PrivateKey, data string) string {
	digest := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest[:]))
}

func arcTestKey() (ed25519.PrivateKey, string) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return key, "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func arcTestAppendSet(t *testing.T, fields []string, n int, key ed25519.PrivateKey) []string {
	t.Helper()
	aar := fmt.Sprintf("ARC-Authentication-Results: i=%d; example.com; dkim=pass\r\n", n)
	amsBare := fmt.Sprintf("ARC-Message-Signature: i=%d; a=ed25519-sha256; c=simple/simple; d=example.com; s=ams; h=From:Date:Subject; bh=%s; b=", n, arcEmptyBodyHash)
	var signedHeaders string
	for _, name := range []string{"From:", "Date:", "Subject:"} {
		for _, field := range fields {
			if strings.HasPrefix(field, name) {
				signedHeaders += field
				break
			}
		}
	}
	ams := amsBare + arcTestSign(key, signedHeaders+amsBare) + "\r\n"
	cv := "pass"
	if n == 1 {
		cv = "none"
	}
	asBare := fmt.Sprintf("ARC-Seal: i=%d; a=ed25519-sha256; cv=%s; d=example.com; s=seal; b=", n, cv)
	var sealInput string
	for i := 1; i < n; i++ {
		for _, prefix := range []string{"ARC-Authentication-Results:", "ARC-Message-Signature:", "ARC-Seal:"} {
			for _, field := range fields {
				if strings.HasPrefix(field, prefix) && strings.Contains(field, fmt.Sprintf("i=%d;", i)) {
					sealInput += arcTestRelaxedHeader(field)
					break
				}
			}
		}
	}
	sealInput += arcTestRelaxedHeader(aar) + arcTestRelaxedHeader(ams) + arcTestRelaxedHeader(asBare+"\r\n")
	sealInput = strings.TrimSuffix(sealInput, "\r\n")
	as := asBare + arcTestSign(key, sealInput) + "\r\n"
	return append(fields, aar, ams, as)
}

func arcTestMessage(t *testing.T, fields []string, record string, dnsFailures map[string]error) (*MMAuth, map[string]int) {
	t.Helper()
	message := strings.Join(fields, "") // final CRLF, with no header/body separator
	if strings.HasSuffix(message, "\r\n\r\n") {
		t.Fatal("fixture has a body separator")
	}
	return arcTestMessageRaw(t, message, record, dnsFailures)
}

func arcTestMessageRaw(t *testing.T, message, record string, dnsFailures map[string]error) (*MMAuth, map[string]int) {
	t.Helper()
	old := domainkey.DefaultResolver
	t.Cleanup(func() { domainkey.DefaultResolver = old })
	queries := map[string]int{}
	domainkey.DefaultResolver = func(name string) ([]string, error) {
		queries[name]++
		if err := dnsFailures[name]; err != nil {
			return nil, err
		}
		switch name {
		case "ams._domainkey.example.com", "seal._domainkey.example.com":
			return []string{record}, nil
		default:
			t.Fatalf("unexpected DNS query: %s", name)
			return nil, nil
		}
	}
	m := NewMMAuth()
	if _, err := m.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.Verify()
	return m, queries
}

func TestRFC8617LatestAMSDetectsHeaderAndBodyChanges(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	changedFrom := append([]string(nil), fields...)
	changedFrom[1] = "From: attacker@example.net\r\n"
	for _, tc := range []struct {
		name, message string
	}{
		{"changed From", strings.Join(changedFrom, "")},
		{"changed body", strings.Join(fields, "") + "\r\nchanged\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := arcTestMessageRaw(t, tc.message, record, nil)
			chain := m.AuthenticationHeaders.ARCSignatures
			if got := chain.GetARCChainValidation(); got != arc.ChainValidationResultFail {
				t.Fatalf("%s chain=%s", tc.name, got)
			}
			if got := chain.GetInstance(1).GetVerifyResult().Status(); got != arc.VerifyStatusFail {
				t.Fatalf("%s AMS=%s", tc.name, got)
			}
		})
	}
}

func arcTestBaseHeaders() []string {
	return []string{
		"Date: Tue, 05 Feb 2019 00:00:00 +0000\r\n",
		"From: a@example.com\r\n",
		"Subject: original\r\n",
	}
}

func TestRFC8617HeaderOnlyIndependentChain(t *testing.T) {
	key, record := arcTestKey()
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fields := arcTestBaseHeaders()
			for n := 1; n <= count; n++ {
				fields = arcTestAppendSet(t, fields, n, key)
			}
			m, queries := arcTestMessage(t, fields, record, nil)
			if m.AuthenticationHeaders.ARCError != nil {
				t.Fatal(m.AuthenticationHeaders.ARCError)
			}
			chain := m.AuthenticationHeaders.ARCSignatures
			if got := chain.GetARCChainValidation(); got != arc.ChainValidationResultPass {
				for _, set := range *chain {
					t.Logf("set %d result=%+v", set.GetInstanceNumber(), set.GetVerifyResult())
				}
				t.Fatalf("chain=%s, want pass: %s", got, chain.GetVerifyResultString())
			}
			if queries["ams._domainkey.example.com"] != count || queries["seal._domainkey.example.com"] != count {
				t.Fatalf("DNS queries=%v", queries)
			}
		})
	}
}

func TestRFC8617HeaderOnlySealingAPI(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestBaseHeaders()
	for n := 1; n <= 2; n++ {
		ams := &arc.ARCMessageSignature{
			InstanceNumber: n, Domain: "example.com", Selector: "ams",
			Canonicalization: "simple/simple", BodyHash: arcEmptyBodyHash, Timestamp: 1700000000,
		}
		if err := ams.Sign(fields, key); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, fmt.Sprintf("ARC-Authentication-Results: i=%d; example.com; dkim=pass\r\n", n), "ARC-Message-Signature: "+ams.String()+"\r\n")
		cv := arc.ChainValidationResultPass
		if n == 1 {
			cv = arc.ChainValidationResultNone
		}
		seal := &arc.ARCSeal{InstanceNumber: n, Domain: "example.com", Selector: "seal", ChainValidation: cv, Timestamp: 1700000000}
		if err := seal.Sign(fields, key); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, "ARC-Seal: "+seal.String()+"\r\n")
		m, _ := arcTestMessage(t, fields, record, nil)
		if got := m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation(); got != arc.ChainValidationResultPass {
			t.Fatalf("after sealing %d sets: chain=%s", n, got)
		}
	}
}

func TestRFC8617HistoricalAMSAndSealFailure(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	fields[2] = "Subject: forwarded\r\n"
	fields = arcTestAppendSet(t, fields, 2, key)
	m, _ := arcTestMessage(t, fields, record, nil)
	chain := m.AuthenticationHeaders.ARCSignatures
	if got := chain.GetARCChainValidation(); got != arc.ChainValidationResultPass {
		t.Fatalf("old AMS modification failed chain: %s", got)
	}
	if got := chain.GetInstance(1).GetVerifyResult().Status(); got != arc.VerifyStatusFail {
		t.Fatalf("old AMS result=%s, want fail", got)
	}
	if got := chain.GetInstance(2).GetVerifyResult().Status(); got != arc.VerifyStatusPass {
		t.Fatalf("latest AMS result=%s, want pass", got)
	}
	for _, tc := range []struct {
		name   string
		prefix string
		old    string
	}{
		{"old seal", "ARC-Seal: i=1;", "b="},
		{"latest AMS", "ARC-Message-Signature: i=2;", "b="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := append([]string(nil), fields...)
			for i, field := range modified {
				if strings.HasPrefix(field, tc.prefix) {
					modified[i] = strings.Replace(field, tc.old, tc.old+"A", 1)
				}
			}
			m, _ := arcTestMessage(t, modified, record, nil)
			if got := m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation(); got != arc.ChainValidationResultFail {
				t.Fatalf("tampered %s chain=%s", tc.name, got)
			}
		})
	}
}

func TestRFC8617IndependentSealScope(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	fields = arcTestAppendSet(t, fields, 2, key)
	dk, err := domainkey.ParseDomainKeyRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := arc.ParseARCHeaders(fields)
	if err != nil {
		t.Fatal(err)
	}
	seal := chain.GetInstance(2).GetARCSeal()
	if got := seal.Verify(fields, &dk).Status(); got != arc.VerifyStatusPass {
		t.Fatalf("original seal=%s", got)
	}
	reordered := append(append([]string(nil), fields[:3]...), fields[8], fields[7], fields[6], fields[5], fields[4], fields[3])
	if got := seal.Verify(reordered, &dk).Status(); got != arc.VerifyStatusPass {
		t.Fatalf("reordered wire headers: seal=%s", got)
	}
	for _, tc := range []struct {
		name, prefix, old, replacement string
	}{
		{"prior AAR", "ARC-Authentication-Results: i=1;", "dkim=pass", "dkim=fail"},
		{"prior AMS", "ARC-Message-Signature: i=1;", "s=ams", "s=other"},
		{"prior AS", "ARC-Seal: i=1;", "s=seal", "s=other"},
		{"current AAR", "ARC-Authentication-Results: i=2;", "dkim=pass", "dkim=fail"},
		{"current AMS", "ARC-Message-Signature: i=2;", "s=ams", "s=other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := append([]string(nil), fields...)
			for i, field := range modified {
				if strings.HasPrefix(field, tc.prefix) {
					modified[i] = strings.Replace(field, tc.old, tc.replacement, 1)
				}
			}
			if got := seal.Verify(modified, &dk).Status(); got != arc.VerifyStatusFail {
				t.Fatalf("modified %s: seal=%s", tc.name, got)
			}
		})
	}
}

func TestRFC8617ForbiddenSealTagsFailPublicChain(t *testing.T) {
	key, record := arcTestKey()
	base := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"missing cv", "cv=none; ", ""},
		{"forbidden h", "b=", "h=From; b="},
		{"forbidden bh", "b=", "bh=AAAA; b="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := append([]string(nil), base...)
			fields[len(fields)-1] = strings.Replace(fields[len(fields)-1], tc.old, tc.replacement, 1)
			m, _ := arcTestMessage(t, fields, record, nil)
			if got := m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation(); got != arc.ChainValidationResultFail {
				t.Fatalf("%s chain=%s", tc.name, got)
			}
		})
	}
}

func TestRFC8617DNSFailureIsPermanentChainFailure(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestAppendSet(t, arcTestBaseHeaders(), 1, key)
	for _, selector := range []string{"ams", "seal"} {
		t.Run(selector, func(t *testing.T) {
			name := selector + "._domainkey.example.com"
			m, queries := arcTestMessage(t, fields, record, map[string]error{name: errors.New("temporary DNS failure")})
			chain := m.AuthenticationHeaders.ARCSignatures
			if got := chain.GetARCChainValidation(); got != arc.ChainValidationResultFail || chain.GetVerifyResultString() != "arc=fail (i=1)" {
				t.Fatalf("DNS failure chain=%s, result=%s", got, chain.GetVerifyResultString())
			}
			if queries[name] != 1 {
				t.Fatalf("queries=%v", queries)
			}
		})
	}
}

func TestRFC8617MaximumFiftySetsAtPublicAPI(t *testing.T) {
	key, record := arcTestKey()
	fields := arcTestBaseHeaders()
	for n := 1; n <= 50; n++ {
		fields = arcTestAppendSet(t, fields, n, key)
	}
	m, queries := arcTestMessage(t, fields, record, nil)
	if got := m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation(); got != arc.ChainValidationResultPass || m.AuthenticationHeaders.ARCSignatures.GetMaxInstance() != 50 {
		t.Fatalf("50 sets: chain=%s", got)
	}
	if queries["ams._domainkey.example.com"] != 50 || queries["seal._domainkey.example.com"] != 50 {
		t.Fatalf("50 sets: queries=%v", queries)
	}
	fields = arcTestAppendSet(t, fields, 51, key)
	m, _ = arcTestMessage(t, fields, record, nil)
	if m.AuthenticationHeaders.ARCError == nil || m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation() != arc.ChainValidationResultFail {
		t.Fatalf("51 sets: error=%v chain=%s", m.AuthenticationHeaders.ARCError, m.AuthenticationHeaders.ARCSignatures.GetARCChainValidation())
	}
}
