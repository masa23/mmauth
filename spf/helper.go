package spf

import (
	"net"
	"strconv"
	"strings"
	"unicode"
)

func isSPFRecord(record string) bool {
	trimmedRecord := strings.TrimSpace(record)
	parts := strings.Fields(trimmedRecord)
	// レコードが "v=spf1" で始まるかどうかをチェックします（大文字小文字を区別しません）
	// Check if the record starts with "v=spf1" (case-insensitive)
	if len(parts) == 0 || strings.ToLower(parts[0]) != "v=spf1" {
		return false
	}

	// レコードにASCII文字のみが含まれ、制御文字が含まれていないことをチェックします
	// Check that the record contains only ASCII characters and no control characters
	for _, r := range record {
		// 表示可能なASCII文字（スペースからチルダまで）とタブを許可します
		// Allow printable ASCII characters (from space to tilde) and tabs
		if r < 32 || r > 126 {
			// タブ（ASCII 9）とスペース（ASCII 32）を許可します
			// Allow tab (ASCII 9) and space (ASCII 32)
			if r != '\t' && r != ' ' {
				return false
			}
		}
	}

	// "v=spf1" の出現回数をカウントします
	// Count occurrences of "v=spf1"
	vSpf1Count := 0
	for _, part := range parts {
		// RFC 4408/7208 では、バージョン識別子 "v=spf1" は大文字小文字を区別しません。
		// したがって、大文字小文字を区別しない方法で比較する必要があります。
		// これにより、"V=spf1" や "v=SPF1" のようなレコードもカウントされ、
		// "v=spf1 ... V=spf1" のような重複がある場合は、正しく permerror になります。
		// In RFC 4408/7208, the version identifier "v=spf1" is case-insensitive.
		// Therefore, comparisons must be done in a case-insensitive manner.
		// This ensures that records like "V=spf1" or "v=SPF1" are also counted,
		// and if there are duplicates like "v=spf1 ... V=spf1", it correctly results in permerror.
		if strings.ToLower(part) == "v=spf1" {
			vSpf1Count++
		}
	}
	if vSpf1Count != 1 {
		return false
	}
	return true
}

// isValidDomain は RFC 1035 および RFC 7208 に従ってドメイン名が有効かどうかをチェックします。
func isValidDomain(domain string) bool {
	// IPリテラル（角括弧で囲まれた文字列）は有効なFQDNと見なされる
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		// 角括弧の中身を取得
		content := domain[1 : len(domain)-1]
		// 中身が空でないこと、および長さが253未満であること
		if len(content) == 0 || len(content) > 253 {
			return false
		}
		// IPアドレスとして有効か確認
		if net.ParseIP(content) == nil {
			return false
		}
		return true
	}

	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// 末尾のドットは許可されます（ルート付きドメイン名）
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	if len(domain) == 0 {
		return false
	}

	// ラベルの数を制限しません。
	// 全体長(<=253)と各ラベル長(<=63)で十分に上限がかかるため、
	// ここでの独自制限は実運用で正当なFQDNを弾く可能性があります。
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		// 有効なドメインには少なくとも2つのラベルが必要です（例：example.com）
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// ラベルは文字または数字で始まり、文字または数字で終わる必要があります
		if !unicode.IsLetter(rune(label[0])) && !unicode.IsDigit(rune(label[0])) {
			return false
		}
		if !unicode.IsLetter(rune(label[len(label)-1])) && !unicode.IsDigit(rune(label[len(label)-1])) {
			return false
		}
		// ラベルの内部には文字、数字、ハイフンを含めることができます
		for i := 0; i < len(label); i++ {
			c := rune(label[i])
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' {
				return false
			}
		}
		// ラベルはハイフンで始まったり終わったりしてはいけません（RFC 1035）
		// Labels must not start or end with a hyphen (RFC 1035)
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// isValidDomainSpec は RFC 7208 に従って domain-spec が有効かどうかをチェックします。
// これは簡略化されたチェックであり、より徹底的なチェックが必要な場合があります。
func isValidDomainSpec(domainSpec string) bool {
	// メモリ使用量を過剰に増加させないように、domainSpecの長さを制限します
	if len(domainSpec) > 253 {
		return false
	}

	// domain-specは基本的な構文チェックに合格する必要があります
	// domain-specにはコロンが含まれることがありますが、トップレベルドメインには含まれません。
	// これは非常に基本的なチェックです。より堅牢な実装が必要です。
	// domain-spec must pass basic syntax checks
	// domain-spec may contain colons, but top-level domains must not contain them.
	// This is a very basic check. A more robust implementation is needed.
	if strings.Contains(domainSpec, "..") {
		return false
	}
	if strings.HasPrefix(domainSpec, ".") || (strings.HasSuffix(domainSpec, ".") && len(domainSpec) > 1) {
		// 先頭のドットは許可されません
		// 末尾のドットは、それが唯一の文字でない場合にのみ許可されます
		// Leading dots are not allowed
		// Trailing dots are only allowed if they are not the only character
		if strings.HasPrefix(domainSpec, ".") {
			return false
		}
	}

	// RFC 7208 の domain-spec は macro-string を許容します。
	// したがって、ここでは「マクロとして現れ得る記号」を過度に弾かないようにします。
	//
	// 具体的には:
	// - ASCII の印字可能文字(0x21..0x7E)のみ許可（空白/制御文字は禁止）
	// - マクロ記法 %{..} の '{' '}' も許可
	//
	// ここで厳密な FQDN 妥当性を強制すると、RFC 上合法な macro-string を
	// 不当に permerror にし得るため、展開後 (expandDomainSpec) の段階で
	// 最低限の妥当性チェックを行う方針に寄せます。
	for i := 0; i < len(domainSpec); i++ {
		b := domainSpec[i]
		// 非ASCIIは禁止
		if b > 0x7F {
			return false
		}
		// 制御文字/空白は禁止
		if b < 0x21 || b > 0x7E {
			return false
		}
	}

	// コロンが含まれている場合、ポート番号付きのドメインまたはマクロである可能性があります
	// とりあえず、コロンの前の部分をチェックします
	// If it contains a colon, it might be a domain with a port number or a macro
	// For now, check the part before the colon
	if strings.Contains(domainSpec, ":") {
		// RFC 7208 8.1/2: domain-specにはコロンが含まれることがありますが、トップレベルドメインには含まれません。
		// ドットで分割してラベルを取得します
		// RFC 7208 8.1/2: domain-spec may contain colons, but top-level domains must not contain them.
		// Split by dots to get labels
		labels := strings.Split(domainSpec, ".")
		if len(labels) > 0 {
			topLabel := labels[len(labels)-1]
			// トップレベルドメインにコロンが含まれている場合は無効です
			// ただし、マクロについては注意が必要です
			// If the top-level domain contains a colon, it's invalid
			// However, care must be taken with macros
			if strings.Contains(topLabel, ":") && !strings.HasPrefix(topLabel, "%") {
				return false
			}
		}

		// 特殊なケース: foo:bar/baz.example.com のような形式
		// この場合、コロンの後の部分をドメイン名として扱う
		// つまり、"foo:bar/baz.example.com" は "bar/baz.example.com" として検証する
		// 最初のコロンの位置を検索
		// Special case: formats like foo:bar/baz.example.com
		// In this case, treat the part after the colon as the domain name
		// That is, "foo:bar/baz.example.com" is validated as "bar/baz.example.com"
		// Find the position of the first colon
		firstColon := strings.Index(domainSpec, ":")
		if firstColon != -1 {
			// 最後のスラッシュの位置を検索
			// Find the position of the last slash
			lastSlash := strings.LastIndex(domainSpec, "/")
			// コロンがスラッシュよりも前にある場合
			// If the colon is before the slash
			if lastSlash != -1 && firstColon < lastSlash {
				// コロンの後の部分をドメイン名として扱う
				// Treat the part after the colon as the domain name
				domainPart := domainSpec[firstColon+1:]
				// ドメイン部分が有効かどうかを検証
				// Validate whether the domain part is valid
				if isValidDomainSpecWithoutColon(domainPart) {
					return true
				} else {
					return false
				}
			}
		}

		// 最初のコロンの前の部分が有効なドメインまたはマクロかどうかをチェックします
		// Check if the part before the first colon is a valid domain or macro
		colonParts := strings.Split(domainSpec, ":")
		if len(colonParts) > 0 {
			// 最初のコロンの前の部分は、有効なドメインまたはマクロである必要があります
			// The part before the first colon must be a valid domain or macro
			if !isValidDomain(colonParts[0]) && !strings.HasPrefix(colonParts[0], "%") {
				return false
			}
		}
	} else {
		return isValidDomainSpecWithoutColon(domainSpec)
	}
	return true
}

// isValidDomainSpecWithoutColon はコロンなしの domain-spec を検証するヘルパー関数です。
func isValidDomainSpecWithoutColon(domainSpec string) bool {
	// コロンがない場合、有効なドメインまたはマクロである必要があります
	// "invalid-domain"テストケースによると、単一のラベル（"foo-bar"など）で構成されるdomain-specは無効と見なされるべきです。
	// これは、domain-specが完全修飾ドメイン名である必要があるためです。
	// 単一のラベルは完全修飾ドメイン名ではありません。
	// ただし、マクロである単一のラベル（%で始まる）は許可されます。
	// If there is no colon, it must be a valid domain or macro
	// According to the "invalid-domain" test case, domain-specs consisting of a single label (like "foo-bar") should be considered invalid.
	// This is because domain-spec must be a fully qualified domain name.
	// A single label is not a fully qualified domain name.
	// However, a single label that is a macro (starting with %) is allowed.
	if !strings.Contains(domainSpec, ".") {
		// 単一のラベルであるかどうかをチェックし、マクロであるかどうかを確認します
		// Check if it's a single label and verify if it's a macro
		if !strings.HasPrefix(domainSpec, "%") {
			// 単一のラベルでマクロでない場合は無効です。
			// Invalid if it's a single label and not a macro.
			return false
		}
		// マクロの場合は、さらに検証を行う必要はありません
		// If it's a macro, no further validation is needed
		return true
	}

	// domainSpecがIPアドレスであるかどうかをチェックします
	// Check if domainSpec is an IP address
	if net.ParseIP(domainSpec) != nil {
		// domain-specはIPアドレスであってはなりません
		// domain-spec must not be an IP address
		return false
	}

	// 各ラベルの有効性をチェックします
	// Check the validity of each label
	labels := strings.Split(domainSpec, ".")
	if len(labels) > 0 {
		// domainSpecがドットで終わる場合、最後のラベルは空になります。
		// これはルート付きドメイン名であり、有効です。
		// このケースを特別に処理する必要があります。
		// If domainSpec ends with a dot, the last label will be empty.
		// This is a rooted domain name and is valid.
		// This case needs special handling.
		endIndex := len(labels)
		if labels[len(labels)-1] == "" {
			// ルート付きドメイン名。最後の空のラベルを検証から除外します
			// Rooted domain name. Exclude the last empty label from validation
			endIndex = len(labels) - 1
		}

		// ラベルが1つだけ（トップレベルドメインになる）かどうかをチェックします
		// これは有効なFQDNではありません
		// Check if there is only one label (which would become the top-level domain)
		// This is not a valid FQDN
		if endIndex <= 1 {
			return false
		}

		for _, label := range labels[:endIndex] {
			// ラベルが'%'で始まる場合、それはマクロであり、検証をスキップします
			// If the label starts with '%', it's a macro and validation is skipped
			if strings.HasPrefix(label, "%") {
				continue
			}
			// RFC 1035に従ってラベルを検証します
			// Validate labels according to RFC 1035
			if len(label) == 0 || len(label) > 63 {
				return false
			}
			// ラベルは文字、数字、またはアンダースコアで始まり、文字または数字で終わる必要があります
			// Labels must start with a letter, digit, or underscore, and end with a letter or digit
			if !unicode.IsLetter(rune(label[0])) && !unicode.IsDigit(rune(label[0])) && label[0] != '_' {
				return false
			}
			if !unicode.IsLetter(rune(label[len(label)-1])) && !unicode.IsDigit(rune(label[len(label)-1])) {
				return false
			}
			// ラベルの内部には文字、数字、ハイフン、スラッシュ（foo:bar/baz.example.comのような特殊ケースの場合）を含めることができます
			// Labels can contain letters, digits, hyphens, slashes (for special cases like foo:bar/baz.example.com) internally
			for j := 0; j < len(label); j++ {
				c := rune(label[j])
				if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' && c != '/' && c != '%' {
					return false
				}
			}
			// ラベルはハイフンで始まったり終わったりしてはいけません（RFC 1035）
			// 特殊ケースのためにラベルがスラッシュで始まったり終わったりすることを許可しますが、両方同時に許可はしません
			// Labels must not start or end with a hyphen (RFC 1035)
			// Labels are allowed to start or end with a slash for special cases, but not both simultaneously
			if label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			// 特殊ケース：ラベルがスラッシュで始まったり終わったりすることを許可しますが、両方同時に許可はしません
			// Special case: Labels are allowed to start or end with a slash, but not both simultaneously
			if label[0] == '/' && label[len(label)-1] == '/' {
				return false
			}
		}

		// トップレベルドメインがマクロでなく、最後の空のラベルでない場合のみチェックします
		// Only check if the top-level domain is not a macro and not the last empty label
		if endIndex > 0 {
			topLabel := labels[endIndex-1]
			// トップラベルがマクロの場合は、数値であるか空であるかをチェックしません
			// If the top label is a macro, it won't be checked for being numeric or empty
			if !strings.HasPrefix(topLabel, "%") {
				// トップレベルドメインのチェックのために末尾のドットを削除します
				// Remove the trailing dot for top-level domain checking
				topLabel = strings.TrimSuffix(topLabel, ".")
				if _, err := strconv.Atoi(topLabel); err == nil {
					// トップレベルドメインが数値であることは許可されません
					// Top-level domains must not be numeric
					return false
				}
				// 末尾のドットを削除した後にトップレベルドメインが空であるかどうかをチェックします
				// ルート付きでないドメインではこれは起こらないはずですが、安全のために確認します
				// Check if the top-level domain is empty after removing the trailing dot
				// This shouldn't happen in non-rooted domains, but check for safety
				if topLabel == "" {
					// これはdomainSpecがドットで終わることを意味し、ルート付きドメインでは有効です
					// このケースは上で既に処理しているので、ここでは起こらないはずです
					// しかし、もし起こった場合は無効なドメイン仕様です
					// This means domainSpec ends with a dot, which is valid for rooted domains
					// This case has already been handled above, so it shouldn't occur here
					// However, if it does, it's an invalid domain specification
					return false
				}
			}
		}
	}
	return true
}
