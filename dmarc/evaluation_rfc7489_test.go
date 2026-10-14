package dmarc

import "testing"

// RFC 7489 §§6.6.2 and 6.6.4: aligned pass wins, temporary failures defer
// policy, and unsampled reject/quarantine step down one policy level.
func TestRFC7489EvaluationAndPolicySampling(t *testing.T) {
	for _, tc := range []struct {
		name       string
		record     Record
		dkim       []DKIMIdentity
		spf        SPFIdentity
		sample     int
		wantStatus EvaluationStatus
		wantPolicy PolicyType
		wantAction PolicyType
		wantSample bool
	}{
		{"aligned SPF", Record{Policy: PolicyReject, Percent: 100}, nil, SPFIdentity{Domain: "example.com", Passed: true}, 99, EvaluationPass, PolicyReject, PolicyNone, false},
		{"aligned DKIM overrides SPF temporary error", Record{Policy: PolicyReject, Percent: 100}, []DKIMIdentity{{Domain: "example.com", Passed: true}}, SPFIdentity{TemporaryError: true}, 0, EvaluationPass, PolicyReject, PolicyNone, false},
		{"aligned SPF overrides DKIM temporary error", Record{Policy: PolicyReject, Percent: 100}, []DKIMIdentity{{Domain: "example.com", TemporaryError: true}}, SPFIdentity{Domain: "example.com", Passed: true}, 0, EvaluationPass, PolicyReject, PolicyNone, false},
		{"aligned SPF temporary error", Record{Policy: PolicyReject, Percent: 100}, nil, SPFIdentity{Domain: "example.com", TemporaryError: true}, 0, EvaluationTempError, PolicyReject, PolicyNone, false},
		{"unaligned SPF temporary error", Record{Policy: PolicyReject, Percent: 100}, nil, SPFIdentity{Domain: "unrelated.org", TemporaryError: true}, 0, EvaluationFail, PolicyReject, PolicyReject, true},
		{"missing SPF identity temporary error", Record{Policy: PolicyReject, Percent: 100}, nil, SPFIdentity{TemporaryError: true}, 0, EvaluationFail, PolicyReject, PolicyReject, true},
		{"DKIM temporary error", Record{Policy: PolicyReject, Percent: 100}, []DKIMIdentity{{Domain: "example.com", TemporaryError: true}}, SPFIdentity{}, 0, EvaluationTempError, PolicyReject, PolicyNone, false},
		{"unaligned DKIM temporary error", Record{Policy: PolicyReject, Percent: 100}, []DKIMIdentity{{Domain: "unrelated.org", TemporaryError: true}}, SPFIdentity{}, 0, EvaluationFail, PolicyReject, PolicyReject, true},
		{"relaxed aligned DKIM temporary error", Record{Policy: PolicyReject, Percent: 100}, []DKIMIdentity{{Domain: "mail.example.com", TemporaryError: true}}, SPFIdentity{}, 0, EvaluationTempError, PolicyReject, PolicyNone, false},
		{"strict unaligned DKIM temporary error", Record{Policy: PolicyReject, AlignmentDKIM: AlignmentStrict, Percent: 100}, []DKIMIdentity{{Domain: "mail.example.com", TemporaryError: true}}, SPFIdentity{}, 0, EvaluationFail, PolicyReject, PolicyReject, true},
		{"reject selected", Record{Policy: PolicyReject, Percent: 25}, nil, SPFIdentity{}, 24, EvaluationFail, PolicyReject, PolicyReject, true},
		{"reject not selected", Record{Policy: PolicyReject, Percent: 25}, nil, SPFIdentity{}, 25, EvaluationFail, PolicyReject, PolicyQuarantine, false},
		{"quarantine not selected", Record{Policy: PolicyQuarantine, Percent: 0}, nil, SPFIdentity{}, 0, EvaluationFail, PolicyQuarantine, PolicyNone, false},
		{"none", Record{Policy: PolicyNone, Percent: 100}, nil, SPFIdentity{}, 0, EvaluationFail, PolicyNone, PolicyNone, true},
		{"subdomain policy", Record{Policy: PolicyReject, SubdomainPolicy: PolicyQuarantine, IsSubdomainPolicy: true, Percent: 100}, nil, SPFIdentity{}, 0, EvaluationFail, PolicyQuarantine, PolicyQuarantine, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluatePolicy(&tc.record, "example.com", tc.dkim, tc.spf, tc.sample)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.wantStatus || got.Policy != tc.wantPolicy || got.Disposition != tc.wantAction || got.Sampled != tc.wantSample {
				t.Fatalf("result=%+v; want status=%s policy=%s action=%s sampled=%t", got, tc.wantStatus, tc.wantPolicy, tc.wantAction, tc.wantSample)
			}
		})
	}
}

func TestRFC7489EvaluationRejectsInvalidSamplingInputs(t *testing.T) {
	for _, sample := range []int{-1, 100} {
		if _, err := EvaluatePolicy(&Record{Policy: PolicyReject, Percent: 100}, "example.com", nil, SPFIdentity{}, sample); err == nil {
			t.Fatalf("accepted sample %d", sample)
		}
	}
	if _, err := EvaluatePolicy(nil, "example.com", nil, SPFIdentity{}, 0); err == nil {
		t.Fatal("accepted nil record")
	}
}
