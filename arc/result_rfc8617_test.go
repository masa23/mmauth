package arc

import "testing"

func TestRFC8617ARCResultFragments(t *testing.T) {
	empty := Signatures{}
	if got := empty.GetVerifyResultString(); got != "arc=none" {
		t.Fatalf("empty chain=%q", got)
	}
	broken, err := ParseARCHeaders([]string{"ARC-Seal: broken\r\n"})
	if err == nil || broken.GetVerifyResultString() != "arc=fail (malformed ARC headers)" {
		t.Fatalf("malformed chain=%q, error=%v", broken.GetVerifyResultString(), err)
	}
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	verified := regressionVerify(t, headers, dk)
	if got := verified.GetVerifyResultString(); got != "arc=pass (i=1)" {
		t.Fatalf("verified chain=%q", got)
	}
}
