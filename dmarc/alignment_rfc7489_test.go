package dmarc

import "testing"

// RFC 7489 Appendix B.1 provides the parent/child and unrelated-domain cases.
func TestRFC7489IdentifierAlignmentExamples(t *testing.T) {
	for _, tc := range []struct {
		name, author, mailFrom string
		dkim                   []AuthenticatedDomain
		spfPass                bool
		adkim, aspf            AlignmentMode
		wantDKIM, wantSPF      bool
	}{
		{"SPF exact", "example.com", "example.com", nil, true, AlignmentRelaxed, AlignmentRelaxed, false, true},
		{"SPF parent relaxed", "example.com", "child.example.com", nil, true, AlignmentRelaxed, AlignmentRelaxed, false, true},
		{"SPF parent strict", "example.com", "child.example.com", nil, true, AlignmentRelaxed, AlignmentStrict, false, false},
		{"SPF unrelated", "child.example.com", "example.net", nil, true, AlignmentRelaxed, AlignmentRelaxed, false, false},
		{"DKIM exact", "example.com", "", []AuthenticatedDomain{{Domain: "example.com", Passed: true}}, false, AlignmentStrict, AlignmentRelaxed, true, false},
		{"DKIM parent relaxed", "child.example.com", "", []AuthenticatedDomain{{Domain: "example.com", Passed: true}}, false, AlignmentRelaxed, AlignmentRelaxed, true, false},
		{"DKIM parent strict", "child.example.com", "", []AuthenticatedDomain{{Domain: "example.com", Passed: true}}, false, AlignmentStrict, AlignmentRelaxed, false, false},
		{"DKIM unrelated", "child.example.com", "", []AuthenticatedDomain{{Domain: "sample.net", Passed: true}}, false, AlignmentRelaxed, AlignmentRelaxed, false, false},
		{"one of multiple DKIM signatures", "example.com", "", []AuthenticatedDomain{{Domain: "example.net", Passed: true}, {Domain: "EXAMPLE.COM", Passed: true}}, false, AlignmentStrict, AlignmentRelaxed, true, false},
		{"failed DKIM signature", "example.com", "", []AuthenticatedDomain{{Domain: "example.com", Passed: false}}, false, AlignmentRelaxed, AlignmentRelaxed, false, false},
		{"SPF authentication failure", "example.com", "example.com", nil, false, AlignmentRelaxed, AlignmentRelaxed, false, false},
		{"default modes are relaxed", "example.com", "child.example.com", nil, true, "", "", false, true},
		{"different private suffix organizations", "alice.github.io", "bob.github.io", nil, true, AlignmentRelaxed, AlignmentRelaxed, false, false},
		{"same co.uk organization", "a.example.co.uk", "b.example.co.uk", nil, true, AlignmentRelaxed, AlignmentRelaxed, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := &Record{AlignmentDKIM: tc.adkim, AlignmentSPF: tc.aspf}
			got, err := EvaluateAlignment(record, tc.author, tc.dkim, tc.mailFrom, tc.spfPass)
			if err != nil {
				t.Fatal(err)
			}
			if got.DKIMAligned != tc.wantDKIM || got.SPFAligned != tc.wantSPF || got.Pass != (tc.wantDKIM || tc.wantSPF) {
				t.Fatalf("alignment=%+v, want DKIM=%t SPF=%t", got, tc.wantDKIM, tc.wantSPF)
			}
		})
	}
}

func TestRFC7489AlignmentInputBoundaries(t *testing.T) {
	if _, err := EvaluateAlignment(nil, "example.com", nil, "", false); err == nil {
		t.Fatal("nil policy record accepted")
	}
	if _, err := EvaluateAlignment(&Record{AlignmentDKIM: "invalid"}, "example.com", nil, "", false); err == nil {
		t.Fatal("invalid alignment mode accepted")
	}
	for _, author := range []string{"", "com", "bad..example.com"} {
		if _, err := EvaluateAlignment(&Record{}, author, nil, "", false); err == nil {
			t.Fatalf("invalid author domain %q accepted", author)
		}
	}
	got, err := EvaluateAlignment(&Record{}, "example.com", []AuthenticatedDomain{{Domain: "com", Passed: true}}, "", false)
	if err != nil || got.Pass {
		t.Fatalf("public suffix authenticated domain: result=%+v error=%v", got, err)
	}
	got, err = EvaluateAlignment(&Record{}, "bücher.example", []AuthenticatedDomain{{Domain: "xn--bcher-kva.example", Passed: true}}, "", false)
	if err != nil || !got.DKIMAligned {
		t.Fatalf("IDNA alignment: result=%+v error=%v", got, err)
	}
}
