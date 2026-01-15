package canonical

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSimpleHeader(t *testing.T) {
	testCases := []struct {
		header string
		want   string
	}{
		{
			"SUBJect: AbC\r\n",
			"SUBJect: AbC\r\n",
		},
		{
			"Subject: Test\r\n",
			"Subject: Test\r\n",
		},
		// RFC 4871 セクション 3.4.1 の要件に基づくテストケース
		{
			"Subject: Test  \r\n",
			"Subject: Test  \r\n",
		},
		{
			"Subject: Test\t\t\r\n",
			"Subject: Test\t\t\r\n",
		},
		{
			"Subject: Test \t \r\n",
			"Subject: Test \t \r\n",
		},
		{
			"Subject: Test\r\n\tContinued\r\n",
			"Subject: Test\r\n\tContinued\r\n",
		},
		{
			"Subject:Test\r\n",
			"Subject:Test\r\n",
		},
		{
			" subject : Test \t \r\n",
			" subject : Test \t \r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := Header(tc.header, Simple)
			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}
}

func TestRelaxedHeader(t *testing.T) {
	testCases := []struct {
		header string
		want   string
	}{
		{
			"SubjeCT: Your Name\r\n",
			"subject:Your Name\r\n",
		},
		{
			"Subject \t:\t Your Name\t \r\n",
			"subject:Your Name\r\n",
		},
		{
			"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n",
			"subject:Kimi No Na Wa\r\n",
		},
		{
			"Subject \t:\t Ki \tmi \t \r\n No \t\r\n Na Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
		{
			"Subject \t:\t Ki \tmi \t \r\n No\r\n\t Na Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
		{
			"Subject: Ki \t mi \t \r\n No\r\n\tNa Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
		// RFC6376の例に基づくテストケース
		{
			"SUBJect: AbC\r\n",
			"subject:AbC\r\n",
		},
		{
			"Subject:  Test  \r\n",
			"subject:Test\r\n",
		},
		// RFC 4871 セクション 3.4.2 の要件に基づくテストケース
		{
			"Subject: Test  \r\n",
			"subject:Test\r\n",
		},
		{
			"Subject: Test\t\t\r\n",
			"subject:Test\r\n",
		},
		{
			"Subject: Test \t \r\n",
			"subject:Test\r\n",
		},
		{
			"Subject: Test\r\n\tContinued\r\n",
			"subject:Test Continued\r\n",
		},
		{
			"Subject:Test\r\n",
			"subject:Test\r\n",
		},
		{
			" subject : Test \t \r\n",
			"subject:Test\r\n",
		},
		{
			"Subject  \t  :  \t  Test  \t  \r\n",
			"subject:Test\r\n",
		},
		{
			"Subject:\r\n Test\r\n",
			"subject:Test\r\n",
		},
		{
			"Subject: \r\n\tTest\r\n",
			"subject:Test\r\n",
		},
		{
			"Subject: Test\r\n\r\nContent\r\n",
			"subject:Test\r\n\r\nContent\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := Header(tc.header, Relaxed)
			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}
}

func TestSimpleBody(t *testing.T) {
	testCases := []struct {
		body []string
		want string
	}{
		{
			[]string{""},
			"\r\n",
		},
		{
			[]string{"\r\n"},
			"\r\n",
		},
		{
			[]string{"\r\n\r\n\r\n"},
			"\r\n",
		},
		{
			[]string{"Hey\r\n\r\n"},
			"Hey\r\n",
		},
		{
			[]string{"Hey\r\nHow r u?\r\n\r\n\r\n"},
			"Hey\r\nHow r u?\r\n",
		},
		{
			[]string{"Hey\r\n\r\nHow r u?"},
			"Hey\r\n\r\nHow r u?\r\n",
		},
		{
			[]string{"What about\nLF endings?\n\n"},
			"What about\r\nLF endings?\r\n",
		},
		{
			[]string{"\r\n", "\r", "\n"},
			"\r\n",
		},
		{
			[]string{"\r\n", "\r"},
			"\r\n\r\r\n",
		},
		{
			[]string{"\r\n", "\r", "\n", "hey\n", "\n"},
			"\r\n\r\nhey\r\n",
		},
		// RFC6376の例に基づくテストケース
		{
			[]string{},
			"\r\n",
		},
		{
			[]string{"Test"},
			"Test\r\n",
		},
		// RFC 4871 セクション 3.4.3 の要件に基づくテストケース
		{
			[]string{"Test "},
			"Test \r\n",
		},
		{
			[]string{"Test\t"},
			"Test\t\r\n",
		},
		{
			[]string{"Test  \t  "},
			"Test  \t  \r\n",
		},
		{
			[]string{"Test\r\n "},
			"Test\r\n \r\n",
		},
		{
			[]string{"Test\r\n\t"},
			"Test\r\n\t\r\n",
		},
		{
			[]string{"Test\r\n  \t  "},
			"Test\r\n  \t  \r\n",
		},
		{
			[]string{"Test\n"},
			"Test\r\n",
		},
		{
			[]string{"Test\n\n"},
			"Test\r\n",
		},
		{
			[]string{"Test\n\n\n"},
			"Test\r\n",
		},
		{
			[]string{"Test", "\n"},
			"Test\r\n",
		},
		{
			[]string{"Test", "\n\n"},
			"Test\r\n",
		},
		{
			[]string{"Test", "\n\n\n"},
			"Test\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			b := bytes.Buffer{}
			wc := SimpleBody(&b)
			for _, body := range tc.body {
				wc.Write([]byte(body))
			}
			wc.Close()
			got := b.String()

			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}
}

func TestRelaxedBody(t *testing.T) {
	testCases := []struct {
		body string
		want string
	}{
		{
			"",
			"\r\n",
		},
		{
			"\r\n",
			"\r\n",
		},
		{
			"\r\n\r\n\r\n",
			"\r\n",
		},
		{
			"Hey\r\n\r\n",
			"Hey\r\n",
		},
		{
			"Hey\r\nHow r u?\r\n\r\n\r\n",
			"Hey\r\nHow r u?\r\n",
		},
		{
			"Hey\r\n\r\nHow r u?",
			"Hey\r\n\r\nHow r u?\r\n",
		},
		{
			"Hey \t you!",
			"Hey you!\r\n",
		},
		{
			"Hey \t \r\nyou!",
			"Hey\r\nyou!\r\n",
		},
		{
			"Hey\r\n \t you!\r\n",
			"Hey\r\n you!\r\n",
		},
		{
			"Hey\r\n \t \r\n \r\n",
			"Hey\r\n",
		},
		// RFC6376の例に基づくテストケース
		{
			"Test  \r\n",
			"Test\r\n",
		},
		{
			"Test\t\t\r\n",
			"Test\r\n",
		},
		// RFC 4871 セクション 3.4.4 の要件に基づくテストケース
		{
			"Test ",
			"Test\r\n",
		},
		{
			"Test\t",
			"Test\r\n",
		},
		{
			"Test  \t  ",
			"Test\r\n",
		},
		{
			"Test\r\n ",
			"Test\r\n",
		},
		{
			"Test\r\n\t",
			"Test\r\n",
		},
		{
			"Test\r\n  \t  ",
			"Test\r\n",
		},
		{
			"Test\n",
			"Test\r\n",
		},
		{
			"Test\n\n",
			"Test\r\n",
		},
		{
			"Test\n\n\n",
			"Test\r\n",
		},
		{
			"Test  \t  \r\n\t  \t  ",
			"Test\r\n",
		},
		{
			"Test\r\n\r\n\r\n",
			"Test\r\n",
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			b := bytes.Buffer{}
			wc := RelaxedBody(&b)
			wc.Write([]byte(tc.body))
			wc.Close()
			got := b.String()

			if got != tc.want {
				t.Errorf("body=%q want %q, but got %q", tc.body, tc.want, got)
			}
		})
	}
}
