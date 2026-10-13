package mmauth

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/dmarc"
	"github.com/masa23/mmauth/domainkey"
	"github.com/masa23/mmauth/spf"
)

func TestRFC7489DMARCResourceLimitsBoundDNSWork(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	for _, tc := range []struct {
		name                     string
		authors, signatures      int
		duplicateAuthorDomains   bool
		policyAvailable          bool
		wantResourceLimitFailure bool
	}{
		{"author domains at limit", maxDMARCAuthorDomains, 0, false, false, false},
		{"author domains over limit", maxDMARCAuthorDomains + 1, 0, false, false, true},
		{"duplicate author domains", maxDMARCAuthorDomains + 1, 0, true, false, false},
		{"DKIM signatures at limit", 1, maxDKIMSignaturesPerMessage, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			dmarc.DefaultResolver = func(string) ([]string, error) {
				queries++
				if tc.policyAvailable {
					return []string{"v=DMARC1; p=none"}, nil
				}
				return nil, nil
			}
			spf.DefaultTXTResolver = func(string) ([]string, error) {
				if !tc.policyAvailable || tc.wantResourceLimitFailure {
					t.Fatal("SPF lookup before policy discovery or resource limit validation")
				}
				return []string{"v=spf1 -all"}, nil
			}
			authors := make([]string, tc.authors)
			for i := range authors {
				domain := fmt.Sprintf("d%d.example.com", i)
				if tc.duplicateAuthorDomains {
					domain = "example.com"
				}
				authors[i] = "a@" + domain
			}
			message := "From: " + strings.Join(authors, ", ") + "\r\n" +
				strings.Repeat("DKIM-Signature: invalid\r\n", tc.signatures) +
				"Date: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n"
			m := NewMMAuth()
			if _, err := m.Write([]byte(message)); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			_, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "a@example.net")
			if (err != nil) != tc.wantResourceLimitFailure {
				t.Fatalf("evaluation error=%v, want resource limit=%t", err, tc.wantResourceLimitFailure)
			}
			if tc.wantResourceLimitFailure && tc.signatures == 0 && queries != 0 {
				t.Fatalf("author limit evaluated after %d DNS queries", queries)
			}
			if tc.policyAvailable && queries != 1 {
				t.Fatalf("signature limit caused %d policy lookups, want 1", queries)
			}
			if !tc.wantResourceLimitFailure && queries == 0 {
				t.Fatal("valid message performed no policy lookup")
			}
		})
	}
}

func TestRFC7489PublicDMARCEvaluation(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	for _, tc := range []struct {
		name, from, mailFrom, record, spfRecord string
		spfErr                                  error
		wantStatus                              dmarc.EvaluationStatus
		wantPolicy, wantAction                  dmarc.PolicyType
	}{
		{"aligned SPF", "From: Alice <alice@example.com>\r\n", "bob@example.com", "v=DMARC1; p=reject", "v=spf1 +all", nil, dmarc.EvaluationPass, dmarc.PolicyReject, dmarc.PolicyNone},
		{"unaligned SPF", "From: Alice <alice@example.com>\r\n", "bob@example.net", "v=DMARC1; p=reject", "v=spf1 +all", nil, dmarc.EvaluationFail, dmarc.PolicyReject, dmarc.PolicyReject},
		{"SPF temporary error", "From: Alice <alice@example.com>\r\n", "bob@example.com", "v=DMARC1; p=reject", "", errors.New("SERVFAIL"), dmarc.EvaluationTempError, dmarc.PolicyReject, dmarc.PolicyNone},
		{"null path uses HELO", "From: Alice <alice@example.com>\r\n", "<>", "v=DMARC1; p=reject", "v=spf1 +all", nil, dmarc.EvaluationFail, dmarc.PolicyReject, dmarc.PolicyReject},
		{"pct zero", "From: Alice <alice@example.com>\r\n", "bob@example.net", "v=DMARC1; p=reject; pct=0", "v=spf1 -all", nil, dmarc.EvaluationFail, dmarc.PolicyReject, dmarc.PolicyQuarantine},
		{"subdomain sp", "From: Alice <alice@sub.example.com>\r\n", "bob@example.net", "v=DMARC1; p=reject; sp=quarantine", "v=spf1 -all", nil, dmarc.EvaluationFail, dmarc.PolicyQuarantine, dmarc.PolicyQuarantine},
		{"IDN From", "From: Alice <alice@bücher.example>\r\n", "bob@example.net", "v=DMARC1; p=reject", "v=spf1 -all", nil, dmarc.EvaluationFail, dmarc.PolicyReject, dmarc.PolicyReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dmarc.DefaultResolver = func(name string) ([]string, error) {
				if name == "_dmarc.example.com" && strings.Contains(tc.from, "sub.example.com") {
					return []string{tc.record}, nil
				}
				if name == "_dmarc.sub.example.com" {
					return nil, nil
				}
				if name == "_dmarc.xn--bcher-kva.example" || name == "_dmarc.example.com" {
					return []string{tc.record}, nil
				}
				return nil, nil
			}
			spf.DefaultTXTResolver = func(name string) ([]string, error) {
				if tc.spfErr != nil {
					return nil, tc.spfErr
				}
				if tc.spfRecord == "" {
					return nil, nil
				}
				return []string{tc.spfRecord}, nil
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte(tc.from + "Date: Tue, 05 Feb 2019 00:00:00 +0000\r\nSubject: test\r\n\r\nbody\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", tc.mailFrom)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.wantStatus || got.Policy != tc.wantPolicy || got.Disposition != tc.wantAction {
				t.Fatalf("result=%+v; want status=%s policy=%s action=%s", got, tc.wantStatus, tc.wantPolicy, tc.wantAction)
			}
		})
	}
}

func TestRFC7489MalformedMailFromCannotPassSPFAlignment(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	dmarc.DefaultResolver = func(string) ([]string, error) {
		return []string{"v=DMARC1; p=reject"}, nil
	}
	spfLookups := 0
	spf.DefaultTXTResolver = func(string) ([]string, error) {
		spfLookups++
		return []string{"v=spf1 +all"}, nil
	}
	for _, mailFrom := range []string{
		"a@@example.com",
		"Alice <a@example.com>",
		"<a@example.com>trailing",
		"a@example.com ()",
		"a@example.com ",
		"a\t@example.com",
		"\"a\" @example.com",
	} {
		t.Run(mailFrom, func(t *testing.T) {
			m := NewMMAuth()
			if _, err := m.Write([]byte("From: a@example.com\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", mailFrom)
			if err != nil || got.Status != dmarc.EvaluationFail || got.Disposition != dmarc.PolicyReject || m.AuthenticationHeaders.SPFResult.Status != spf.None || spfLookups != 0 {
				t.Fatalf("MAIL FROM %q: result=%+v SPF=%+v lookups=%d error=%v", mailFrom, got, m.AuthenticationHeaders.SPFResult, spfLookups, err)
			}
		})
	}
}

func TestRFC7489InvalidFromFieldNameIsNotAuthor(t *testing.T) {
	if _, err := authorDomainsFromHeaders(headers{"From : a@example.com\r\n"}); err == nil {
		t.Fatal("invalid From field name was accepted as an author field")
	}
}

func TestRFC7489FromRequiresMailboxList(t *testing.T) {
	for _, from := range []string{
		"From: Friends: a@example.com, b@example.net;\r\n",
		"From: Friends: a@example.com;\r\n",
	} {
		if domains, err := authorDomainsFromHeaders(headers{from}); err == nil {
			t.Fatalf("group From accepted: %q -> %v", from, domains)
		}
	}
	for _, from := range []string{
		"From: \"Friends: ops\" <a@example.com>, b@example.net\r\n",
		"From: a@example.com (note: detail), b@example.net\r\n",
	} {
		if domains, err := authorDomainsFromHeaders(headers{from}); err != nil || len(domains) != 2 {
			t.Fatalf("mailbox-list rejected: %q -> %v, %v", from, domains, err)
		}
	}
}

func TestRFC7489PublicDMARCDKIMIntegration(t *testing.T) {
	oldDMARC, oldSPF, oldDKIM := dmarc.DefaultResolver, spf.DefaultTXTResolver, domainkey.DefaultResolver
	t.Cleanup(func() {
		dmarc.DefaultResolver, spf.DefaultTXTResolver, domainkey.DefaultResolver = oldDMARC, oldSPF, oldDKIM
	})
	dmarc.DefaultResolver = func(name string) ([]string, error) {
		if name != "_dmarc.football.example.com" {
			t.Fatalf("unexpected DMARC lookup %q", name)
		}
		return []string{"v=DMARC1; p=reject"}, nil
	}
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	for _, tc := range []struct {
		name   string
		dnsErr error
		want   dmarc.EvaluationStatus
	}{
		{"aligned DKIM passes", nil, dmarc.EvaluationPass},
		{"DKIM DNS temporary failure", errors.New("SERVFAIL"), dmarc.EvaluationTempError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			domainkey.DefaultResolver = func(name string) ([]string, error) {
				lookups++
				if tc.dnsErr != nil {
					return nil, tc.dnsErr
				}
				switch name {
				case "brisbane._domainkey.football.example.com":
					return []string{rfc8463EdRecord}, nil
				case "test._domainkey.football.example.com":
					return []string{rfc8463RSARecord}, nil
				default:
					t.Fatalf("unexpected DKIM lookup %q", name)
					return nil, nil
				}
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte(rfc8463MessageWithCRLF())); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "sender@example.net")
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.want || got.Disposition != dmarc.PolicyNone || lookups != 2 {
				t.Fatalf("result=%+v; DKIM lookups=%d", got, lookups)
			}
		})
	}
}

func TestRFC7489DMARCReverifiesCachedDKIMWithDNSKey(t *testing.T) {
	oldDMARC, oldSPF, oldDKIM := dmarc.DefaultResolver, spf.DefaultTXTResolver, domainkey.DefaultResolver
	t.Cleanup(func() {
		dmarc.DefaultResolver, spf.DefaultTXTResolver, domainkey.DefaultResolver = oldDMARC, oldSPF, oldDKIM
	})
	dmarc.DefaultResolver = func(string) ([]string, error) { return []string{"v=DMARC1; p=reject"}, nil }
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	m := NewMMAuth()
	if _, err := m.Write([]byte(rfc8463MessageWithCRLF())); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, sig := range *m.AuthenticationHeaders.DKIMSignatures {
		record := rfc8463RSARecord
		if sig.Selector == "brisbane" {
			record = rfc8463EdRecord
		}
		key, err := domainkey.ParseDomainKeyRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		can := sig.GetCanonicalizationAndAlgorithm()
		bodyHash := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{
			Body: Canonicalization(can.Body), Algorithm: can.HashAlgo,
			Limit: sig.Limit, LimitSet: sig.LimitSet,
		})
		sig.Verify(m.Headers, bodyHash, &key)
		if sig.VerifyResult.Status() != dkim.VerifyStatusPass {
			t.Fatalf("cached verification for %s: %s", sig.Selector, sig.VerifyResult.Status())
		}
	}
	lookups := 0
	domainkey.DefaultResolver = func(string) ([]string, error) { lookups++; return nil, nil }
	got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "sender@example.net")
	if err != nil || got.Status != dmarc.EvaluationFail || got.Disposition != dmarc.PolicyReject || lookups != 2 {
		t.Fatalf("result=%+v error=%v DKIM DNS lookups=%d", got, err, lookups)
	}
}

func TestRFC7489PublicDMARCPolicyDiscoveryErrors(t *testing.T) {
	old := dmarc.DefaultResolver
	t.Cleanup(func() { dmarc.DefaultResolver = old })
	for _, tc := range []struct {
		name      string
		lookupErr error
		want      dmarc.EvaluationStatus
		wantErr   bool
	}{
		{"no record", nil, dmarc.EvaluationNone, false},
		{"DNS temporary error", errors.New("SERVFAIL"), dmarc.EvaluationTempError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dmarc.DefaultResolver = func(string) ([]string, error) { return nil, tc.lookupErr }
			m := NewMMAuth()
			if _, err := m.Write([]byte("From: a@example.com\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "sender@example.net")
			if got.Status != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("result=%+v error=%v", got, err)
			}
		})
	}
}

func TestRFC7489PublicDMARCRejectsAmbiguousFrom(t *testing.T) {
	for _, from := range []string{
		"Subject: missing\r\n", "From: a@example.com\r\nFrom: b@example.com\r\n",
		"From: malformed\r\n",
	} {
		m := NewMMAuth()
		if _, err := m.Write([]byte(from + "Date: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "a@example.com"); err == nil {
			t.Fatalf("accepted ambiguous From %q", from)
		}
	}
}

func TestRFC7489MultivaluedFromSelectsStrictestFailedPolicy(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	for _, tc := range []struct {
		name, firstRecord, secondRecord string
		wantAction                      dmarc.PolicyType
	}{
		{"reject selected", "v=DMARC1; p=quarantine", "v=DMARC1; p=reject", dmarc.PolicyReject},
		{"reject unsampled", "v=DMARC1; p=quarantine", "v=DMARC1; p=reject; pct=0", dmarc.PolicyQuarantine},
		{"later sampled reject wins", "v=DMARC1; p=reject; pct=0", "v=DMARC1; p=reject", dmarc.PolicyReject},
		{"earlier sampled reject wins", "v=DMARC1; p=reject", "v=DMARC1; p=reject; pct=0", dmarc.PolicyReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queried []string
			dmarc.DefaultResolver = func(name string) ([]string, error) {
				queried = append(queried, name)
				switch name {
				case "_dmarc.example.com":
					return []string{tc.firstRecord}, nil
				case "_dmarc.example.net":
					return []string{tc.secondRecord}, nil
				default:
					t.Fatalf("unexpected DMARC lookup %q", name)
					return nil, nil
				}
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte("From: a@example.com,\r\n b@example.net\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.org", "a@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != dmarc.EvaluationFail || got.Policy != dmarc.PolicyReject || got.Disposition != tc.wantAction || len(queried) != 2 {
				t.Fatalf("result=%+v queries=%v", got, queried)
			}
		})
	}
}

func TestRFC7489MultivaluedFromContinuesAfterPolicyLookupError(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	for _, tc := range []struct {
		name, from, validPolicy string
		lookupErr               error
		wantStatus              dmarc.EvaluationStatus
		wantAction              dmarc.PolicyType
		wantErr                 bool
	}{
		{"DNS error first, reject second", "a@example.com, b@example.net", "reject", errors.New("SERVFAIL"), dmarc.EvaluationFail, dmarc.PolicyReject, false},
		{"reject first, DNS error second", "b@example.net, a@example.com", "reject", errors.New("SERVFAIL"), dmarc.EvaluationFail, dmarc.PolicyReject, false},
		{"multiple records first, reject second", "a@example.com, b@example.net", "reject", nil, dmarc.EvaluationFail, dmarc.PolicyReject, false},
		{"DNS error and none policy", "a@example.com, b@example.net", "none", errors.New("SERVFAIL"), dmarc.EvaluationTempError, dmarc.PolicyNone, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			dmarc.DefaultResolver = func(name string) ([]string, error) {
				lookups++
				switch name {
				case "_dmarc.example.com":
					if tc.lookupErr == nil {
						return []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, nil
					}
					return nil, tc.lookupErr
				case "_dmarc.example.net":
					return []string{"v=DMARC1; p=" + tc.validPolicy}, nil
				default:
					t.Fatalf("unexpected DMARC lookup %q", name)
					return nil, nil
				}
			}
			m := NewMMAuth()
			if _, err := m.Write([]byte("From: " + tc.from + "\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.org", "sender@example.org")
			if got.Status != tc.wantStatus || got.Disposition != tc.wantAction || (err != nil) != tc.wantErr || lookups != 2 {
				t.Fatalf("result=%+v error=%v lookups=%d", got, err, lookups)
			}
		})
	}
}

func TestRFC7489EquivalentIDNAuthorsEvaluatedOnce(t *testing.T) {
	oldDMARC, oldSPF := dmarc.DefaultResolver, spf.DefaultTXTResolver
	t.Cleanup(func() { dmarc.DefaultResolver, spf.DefaultTXTResolver = oldDMARC, oldSPF })
	lookups := 0
	dmarc.DefaultResolver = func(name string) ([]string, error) {
		if name != "_dmarc.xn--bcher-kva.example" {
			t.Fatalf("unexpected DMARC lookup %q", name)
		}
		lookups++
		return []string{"v=DMARC1; p=reject; pct=100"}, nil
	}
	spf.DefaultTXTResolver = func(string) ([]string, error) { return []string{"v=spf1 -all"}, nil }
	m := NewMMAuth()
	const message = "From: Alice <alice@bücher.example>, Bob <bob@xn--bcher-kva.example>\r\nDate: Tue, 05 Feb 2019 00:00:00 +0000\r\n\r\nbody\r\n"
	if _, err := m.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := m.EvaluateDMARC(net.ParseIP("192.0.2.1"), "helo.example.net", "sender@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 || got.Status != dmarc.EvaluationFail || got.Disposition != dmarc.PolicyReject {
		t.Fatalf("equivalent IDNs evaluated %d times: %+v", lookups, got)
	}
}
