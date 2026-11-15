package dkim2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// draft-ietf-dkim-dkim2-spec-09, sections 4 and 6.2: field names are
// alphabetized, repeated fields are read bottom-up, and trace fields are
// excluded. The expected octets are written independently of headerDigest.
func TestDraftHeaderCanonicalization(t *testing.T) {
	headers := []string{
		"SUBJECT: newest\t value \t\r\n",
		"Received: first\r\n",
		"From:  Alice\r\n\t Example  <a@example.com>  \r\n",
		"Subject:\tolder\r\n",
		"X-Trace: ignored\r\n",
		"Received-SPF: ignored\r\n",
		"DKIM-Signature: ignored\r\n",
		"Message-Instance: ignored\r\n",
		"DKIM2-Signature: ignored\r\n",
	}
	wantBytes := []byte("from:Alice Example <a@example.com>\r\nsubject:older\r\nsubject:newest value\r\n")
	want := sha256.Sum256(wantBytes)
	got, err := headerDigest(headers, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("header digest = %s, want digest of %q", got, wantBytes)
	}
	for _, field := range []string{"Apparently-To", "ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal", "Authentication-Results", "Delivered-To", "DL-Expansion-History", "Original-Recipient", "Return-Path", "SIO-Label-History", "X400-Received", "X400-Trace"} {
		t.Run(field, func(t *testing.T) {
			withTrace := append(append([]string(nil), headers...), field+": new trace\r\n")
			got, err := headerDigest(withTrace, "sha256")
			if err != nil || got != base64.StdEncoding.EncodeToString(want[:]) {
				t.Fatalf("unsigned %s changed digest: %s, %v", field, got, err)
			}
		})
	}
	changed := append(append([]string(nil), headers...), "Comments: signed\r\n")
	if got, err := headerDigest(changed, "sha256"); err != nil || got == base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("new signed field did not change digest: %s, %v", got, err)
	}
	for _, field := range []string{"Auto-Submitted", "VBR-Info"} {
		changed := append(append([]string(nil), headers...), field+": now signed\r\n")
		if got, err := headerDigest(changed, "sha256"); err != nil || got == base64.StdEncoding.EncodeToString(want[:]) {
			t.Fatalf("newly signed %s did not change digest: %s, %v", field, got, err)
		}
	}
}

// Section 6.1 uses DKIM1 simple body canonicalization: only empty trailing
// lines are removed, and the canonical body always ends with one CRLF.
func TestDraftBodyCanonicalization(t *testing.T) {
	for _, tc := range []struct{ name, body, canonical string }{
		{"empty", "", "\r\n"},
		{"only empty lines", "\r\n\r\n", "\r\n"},
		{"missing final CRLF", "abc", "abc\r\n"},
		{"trailing empty lines", "abc\r\n\r\n\r\n", "abc\r\n"},
		{"nonempty whitespace line", "abc\r\n \r\n\r\n", "abc\r\n \r\n"},
		{"interior empty line", "a\r\n\r\nb", "a\r\n\r\nb\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := sha256.Sum256([]byte(tc.canonical))
			got, err := bodyDigest([]byte(tc.body), "sha256")
			if err != nil || got != base64.StdEncoding.EncodeToString(want[:]) {
				t.Fatalf("body digest = %s, %v; want digest of %q", got, err, tc.canonical)
			}
		})
	}
}

// Sections 8, 9, 10 and 14.2 require strict tag and sequence validation.
func TestDraftMalformedTagsAndSequences(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	mi := []byte("Message-Instance: m=1;")
	sig := []byte("DKIM2-Signature: i=1;")
	if !bytes.Contains(wire, mi) || !bytes.Contains(wire, sig) {
		t.Fatal("unexpected signed wire format")
	}
	options := VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}
	if got := Verify(wire, env, options); got.Status != Pass {
		t.Fatalf("baseline status = %s: %v", got.Status, got.Err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"missing instance", func(w []byte) []byte { return removeField(w, "Message-Instance") }},
		{"missing signature", func(w []byte) []byte { return removeField(w, "DKIM2-Signature") }},
		{"instance gap", func(w []byte) []byte { return bytes.Replace(w, mi, []byte("Message-Instance: m=2;"), 1) }},
		{"signature gap", func(w []byte) []byte { return bytes.Replace(w, sig, []byte("DKIM2-Signature: i=2;"), 1) }},
		{"duplicate instance tag", func(w []byte) []byte { return bytes.Replace(w, mi, []byte("Message-Instance: m=1; M=1;"), 1) }},
		{"empty tag between semicolons", func(w []byte) []byte { return bytes.Replace(w, mi, []byte("Message-Instance: m=1;;"), 1) }},
		{"empty recipe", func(w []byte) []byte { return bytes.Replace(w, mi, []byte("Message-Instance: m=1; r=;"), 1) }},
		{"duplicate signature tag", func(w []byte) []byte { return bytes.Replace(w, sig, []byte("DKIM2-Signature: i=1; I=1;"), 1) }},
		{"empty flags", func(w []byte) []byte { return bytes.Replace(w, sig, []byte("DKIM2-Signature: i=1; f=;"), 1) }},
		{"invalid nonce", func(w []byte) []byte {
			return bytes.Replace(w, []byte(";\r\n\ts=s1:"), []byte(";\r\n\tn="+strings.Repeat("x", 65)+";\r\n\ts=s1:"), 1)
		}},
		{"duplicate selector", func(w []byte) []byte { return bytes.Replace(w, []byte("s=s1:"), []byte("s=s1:future:,s1:"), 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := tc.mutate(wire)
			if bytes.Equal(changed, wire) {
				t.Fatal("mutation did not change the signed wire")
			}
			got := Verify(changed, env, options)
			if got.Status != PermError {
				t.Fatalf("status = %s, want permerror: %v", got.Status, got.Err)
			}
		})
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	h := parsed.Instances[0].Hashes[0]
	duplicateHash := "Message-Instance: m=1; h=sha256:" + h.Header + ":" + h.Body + ",sha256:" + h.Header + ":" + h.Body + ";\r\n"
	for name, changed := range map[string][]byte{
		"duplicate hash algorithm": bytes.Replace(wire, []byte(parsed.Instances[0].Raw), []byte(duplicateHash), 1),
		"unsigned newer instance":  append([]byte(strings.Replace(parsed.Instances[0].Raw, "m=1", "m=2", 1)), wire...),
	} {
		t.Run(name, func(t *testing.T) {
			got := Verify(changed, env, options)
			if got.Status != PermError {
				t.Fatalf("status = %s, want permerror: %v", got.Status, got.Err)
			}
		})
	}
}

func removeField(wire []byte, name string) []byte {
	lines := bytes.Split(wire, []byte("\r\n"))
	var out [][]byte
	remove := false
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte(name+":")) {
			remove = true
			continue
		}
		if remove && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		remove = false
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\r\n"))
}

// Sections 14.3 and 14.4 define a 14-day age limit and exact SMTP path
// matching, except that domain labels are compared without case.
func TestDraftTimeAndEnvelopeBoundaries(t *testing.T) {
	key := edKey()
	env := Envelope{"<Alice@EXAMPLE.COM>", []string{"<Bob@RELAY.TEST>", "<extra@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	resolver := records{"s1._domainkey.example.com": {keyRecord(key)}}
	for _, tc := range []struct {
		name string
		env  Envelope
		now  time.Time
		want Status
	}{
		{"exact 14 days", Envelope{"<Alice@example.com>", []string{"<Bob@relay.test>"}}, testTime.Add(14 * 24 * time.Hour), Pass},
		{"expired by one second", env, testTime.Add(14*24*time.Hour + time.Second), Fail},
		{"future within one day", env, testTime.Add(-time.Second), Pass},
		{"future beyond one day", env, testTime.Add(-24*time.Hour - time.Second), Fail},
		{"MAIL FROM local part case", Envelope{"<alice@example.com>", env.RcptTo}, testTime, Fail},
		{"RCPT TO local part case", Envelope{env.MailFrom, []string{"<bob@relay.test>"}}, testTime, Fail},
		{"unrecorded recipient", Envelope{env.MailFrom, []string{"<other@relay.test>"}}, testTime, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Verify(wire, tc.env, VerifyOptions{Resolver: resolver, Now: tc.now})
			if got.Status != tc.want {
				t.Fatalf("status = %s, want %s: %v", got.Status, tc.want, got.Err)
			}
		})
	}
}

// Section 14.5 and the DKIM2 DNS draft require malformed and revoked DNS
// keys to fail permanently. The retired h=, n=, s= and t= tags have no effect.
func TestDraftDNSKeyRules(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime})
	if err != nil {
		t.Fatal(err)
	}
	valid := keyRecord(key)
	pStart := strings.Index(valid, "p=") + len("p=")
	folded := valid[:pStart+16] + "\r\n\t" + valid[pStart+16:]
	for _, tc := range []struct {
		name, record string
		want         Status
	}{
		{"retired h tag ignored", valid, Pass},
		{"folded public key", folded, Pass},
		{"retired s tag ignored", valid + "; s=other", Pass},
		{"revoked", "v=DKIM1; k=ed25519; p=", PermError},
		{"wrong key algorithm", strings.Replace(valid, "k=ed25519", "k=rsa", 1), PermError},
		{"duplicate p tag", valid + "; p=bogus", PermError},
		{"version not first", strings.Replace(valid, "v=DKIM1; k=ed25519", "k=ed25519; v=DKIM1", 1), PermError},
		{"invalid version", strings.Replace(valid, "v=DKIM1", "v=DKIM2", 1), PermError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {tc.record}}, Now: testTime})
			if got.Status != tc.want {
				t.Fatalf("status = %s, want %s: %v", got.Status, tc.want, got.Err)
			}
		})
	}
	if got := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {"v=DKIM3; k=ed25519; p=ignored", valid}}, Now: testTime}); got.Status != Pass {
		t.Fatalf("unrelated TXT version affected key selection: %s, %v", got.Status, got.Err)
	}
}

// Section 5 numbers equal-named headers bottom-up and body lines top-down.
// This vector also checks that copy and data steps retain their stated order.
func TestDraftRecipeOrderingAndSyntax(t *testing.T) {
	// Section 5.1 now forbids Recipes for unsigned fields.
	if _, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(`{"h":{"received":[]}}`))); err == nil {
		t.Fatal("Recipe for an unsigned field was accepted")
	}
	m, err := Parse([]byte("From: a@example.com\r\nSubject: top\r\nSubject: bottom\r\n\r\none\r\ntwo\r\nthree\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"h":{"subject":[{"c":[1,1]},{"d":[" restored"]}]},"b":[{"c":[1,1]},{"d":["middle"]},{"c":[3,3]}]}`))
	recipe, err := parseRecipe(encoded)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := applyRecipe(m, recipe)
	if err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for _, field := range previous.Headers {
		if strings.HasPrefix(strings.ToLower(field), "subject:") {
			subjects = append(subjects, field)
		}
	}
	if got, want := strings.Join(subjects, ""), "subject: restored\r\nSubject: bottom\r\n"; got != want {
		t.Fatalf("recreated subjects = %q, want %q", got, want)
	}
	if got, want := string(previous.Body), "one\r\nmiddle\r\nthree\r\n"; got != want {
		t.Fatalf("recreated body = %q, want %q", got, want)
	}
	for _, tc := range []struct{ name, json string }{
		{"no operation", `{}`},
		{"uppercase header name", `{"h":{"Subject":[]}}`},
		{"zero copy index", `{"b":[{"c":[0,1]}]}`},
		{"overlapping copy ranges", `{"b":[{"c":[1,2]},{"c":[2,3]}]}`},
		{"two operations in step", `{"b":[{"c":[1,1],"d":["x"]}]}`},
		{"CR in data", `{"b":[{"d":["x\ry"]}]}`},
		{"LF in data", `{"h":{"subject":[{"d":["x\ny"]}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(tc.json))
			if _, err := parseRecipe(encoded); err == nil {
				t.Fatal("invalid Recipe accepted")
			}
		})
	}
}

func TestDraft09RecipeByteDataAndDuplicateKeys(t *testing.T) {
	m, err := Parse([]byte("From: a@example.com\r\nSubject: now\r\n\r\nnow\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"h":{"subject":[{"u":["/w=="]}]} ,"b":[{"u":["/g=="]}]}`))
	r, err := parseRecipe(encoded)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := applyRecipe(m, r)
	if err != nil || string(previous.Body) != "\xfe\r\n" {
		t.Fatalf("binary body reconstruction=%q: %v", previous.Body, err)
	}
	if !bytes.Contains([]byte(strings.Join(previous.Headers, "")), []byte{'s', 'u', 'b', 'j', 'e', 'c', 't', ':', 0xff}) {
		t.Fatalf("binary header reconstruction=%q", previous.Headers)
	}
	for _, value := range []string{
		`{"h":{"subject":[],"subject":[]}}`,
		`{"H":{},"b":[]}`,
		`{"b":[{"u":["/w=="],"u":["/g=="]}]}`,
		`{"b":[{"u":["/w==\n"]}]}`,
		`{"b":[{"u":["Cg=="]}]}`,
	} {
		if _, err := parseRecipe(base64.StdEncoding.EncodeToString([]byte(value))); err == nil {
			t.Fatalf("invalid Recipe accepted: %s", value)
		}
	}
}

// Sections 10.10 and 12.5 treat retired flags as unknown and forbid exploded
// on the first signature.
func TestDraftFlagRules(t *testing.T) {
	key := edKey()
	env := Envelope{"<alice@example.com>", []string{"<bob@relay.test>"}}
	for _, flag := range []string{"donotmodify", "donotexplode", "futureflag"} {
		wire, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime, Flags: []string{flag}})
		if err != nil {
			t.Fatal(err)
		}
		if got := Verify(wire, env, VerifyOptions{Resolver: records{"s1._domainkey.example.com": {keyRecord(key)}}, Now: testTime}); got.Status != Pass {
			t.Fatalf("unknown flag %s: %s, %v", flag, got.Status, got.Err)
		}
	}
	if _, err := Sign(original(), SignOptions{Domain: "example.com", Selector: "s1", Key: key, Envelope: env, Timestamp: testTime, Flags: []string{"exploded"}}); err == nil {
		t.Fatal("initial exploded flag accepted")
	}
}
