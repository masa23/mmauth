package mmauth

import (
	"fmt"
	"strings"
	"testing"
)

func TestDKIMSignatureLimitPrecedesBodyHashRegistration(t *testing.T) {
	for _, count := range []int{maxDKIMSignaturesPerMessage, maxDKIMSignaturesPerMessage + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var message strings.Builder
			message.WriteString("From: a@example.com\r\n")
			for i := 1; i <= count; i++ {
				fmt.Fprintf(&message, "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s; c=relaxed/relaxed; h=from; bh=AAAA; b=AAAA; l=%d\r\n", i)
			}
			message.WriteString("\r\nbody\r\n")
			m := NewMMAuth()
			_, writeErr := m.Write([]byte(message.String()))
			closeErr := m.Close()
			if count > maxDKIMSignaturesPerMessage {
				if writeErr == nil && closeErr == nil {
					t.Fatal("excessive signatures accepted")
				}
				if len(m.bodyHashList) != 0 || len(m.bodyHashed) != 0 {
					t.Fatalf("body hashes registered before rejection: modes=%d hashes=%d", len(m.bodyHashList), len(m.bodyHashed))
				}
				return
			}
			if writeErr != nil || closeErr != nil {
				t.Fatalf("signatures at limit rejected: write=%v close=%v", writeErr, closeErr)
			}
			if len(m.bodyHashList) != count || len(m.bodyHashed) != count {
				t.Fatalf("body hash modes=%d hashes=%d, want %d", len(m.bodyHashList), len(m.bodyHashed), count)
			}
		})
	}
}
