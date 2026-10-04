package arc

import (
	"strings"
	"testing"
)

func TestARCSealIgnoresMalformedLaterSets(t *testing.T) {
	key, dk := regressionARCKey(t)
	headers := regressionAddSet(t, []string{"From: a@example.com\r\n"}, 1, ChainValidationResultNone, key)
	headers = regressionAddSet(t, headers, 2, ChainValidationResultPass, key)
	sigs, err := ParseARCHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	seal := sigs.GetInstance(1).GetARCSeal()
	if result := seal.Verify(headers, dk); result.Status() != VerifyStatusPass {
		t.Fatalf("valid later set: %s, %v", result.Status(), result.Error())
	}

	for _, prefix := range []string{"ARC-Message-Signature:", "ARC-Seal:"} {
		for _, instance := range []string{"i=1;", "i=2;"} {
			t.Run(prefix+instance, func(t *testing.T) {
				input := append([]string(nil), headers...)
				for i, raw := range input {
					if strings.HasPrefix(raw, prefix) && strings.Contains(raw, instance) {
						input[i] = strings.Replace(raw, "a=ed25519-sha256;", "", 1)
					}
				}
				want := VerifyStatusFail
				if instance == "i=2;" {
					want = VerifyStatusPass
				}
				if result := seal.Verify(input, dk); result.Status() != want {
					t.Fatalf("seal i=1: got %s, want %s: %v", result.Status(), want, result.Error())
				}
				chain, err := ParseARCHeaders(input)
				if err == nil || chain.GetVerifyResult() != VerifyStatusFail {
					t.Fatal("full-chain parsing must reject malformed sets")
				}
			})
		}
	}
	for _, prefix := range []string{"ARC-Authentication-Results:", "ARC-Message-Signature:", "ARC-Seal:"} {
		t.Run("duplicate later "+prefix, func(t *testing.T) {
			input := append([]string(nil), headers...)
			for _, raw := range headers {
				if strings.HasPrefix(raw, prefix) && strings.Contains(raw, "i=2;") {
					input = append(input, raw)
				}
			}
			if result := seal.Verify(input, dk); result.Status() != VerifyStatusPass {
				t.Fatalf("duplicate later set affected seal i=1: %s, %v", result.Status(), result.Error())
			}
			chain, err := ParseARCHeaders(input)
			if err == nil || chain.GetVerifyResult() != VerifyStatusFail {
				t.Fatal("full-chain parsing must reject duplicate headers")
			}
		})
	}

	for _, instance := range []string{"", "i=invalid;", "i=51;", "i=2; i=1;"} {
		t.Run("unidentifiable later set "+instance, func(t *testing.T) {
			input := append([]string(nil), headers...)
			input[len(input)-1] = strings.Replace(input[len(input)-1], "i=2;", instance, 1)
			if result := seal.Verify(input, dk); result.Status() != VerifyStatusFail {
				t.Fatalf("invalid or ambiguous instance was ignored: %s", result.Status())
			}
		})
	}
	failed := *seal
	failed.ChainValidation = ChainValidationResultFail
	if result := failed.Verify(headers, dk); result.Status() != VerifyStatusFail {
		t.Fatal("cv=fail must remain a failure")
	}
}
