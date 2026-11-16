package domainkey

import (
	"errors"
	"testing"
)

func TestExplicitKeyTypes(t *testing.T) {
	for _, tc := range []struct {
		tag     string
		want    KeyType
		invalid bool
	}{
		{"", "", false}, {"k=rsa; ", KeyTypeRSA, false}, {"k=ed25519; ", KeyTypeED25519, false},
		{"k=unsupported; ", "", true}, {"k=; ", "", true}, {"k=rsa:ed25519; ", "", true}, {"k=rsa:unsupported; ", "", true},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			key, e := ParseDomainKeyRecord("v=DKIM1; " + tc.tag + "p=AA==")
			if tc.invalid {
				if !errors.Is(e, ErrInvalidKeyType) {
					t.Fatalf("invalid key type accepted: key=%+v error=%v", key, e)
				}
				return
			}
			if e != nil || key.KeyType != tc.want {
				t.Fatalf("key type=%q want=%q error=%v", key.KeyType, tc.want, e)
			}
		})
	}
}
