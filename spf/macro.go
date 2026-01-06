package spf

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// DNSResolverインターフェースは、DNSルックアップ機能を提供します。
type DNSResolver interface {
	ReplaceMacroValues(s string, ctx MacroContext, purpose MacroPurpose) (string, error)
}

// ReplaceMacroValuesはdnsResolverImplのDNSResolverインターフェースを実装します。
func (d *dnsResolverImpl) ReplaceMacroValues(domainSpec string, ctx MacroContext, purpose MacroPurpose) (string, error) {
	tokens, err := parseMacroString(domainSpec)
	if err != nil {
		return "", err
	}
	ptr := ""
	// MacroClientPTRが含まれる場合はPTRルックアップをする
	for _, tok := range tokens {
		if tok.Kind == TokenMacro && tok.Macro.Letter == rune(MacroClientPTR) {
			// %{p} は PTR を参照します。ptr メカニズムと同様に、
			// domain-spec 用の展開（include/redirect/exists 等）では 10-term 制限の対象に含めます。
			// exp= 用は pyspf 互換を優先して term 制限の対象外にします。
			if purpose == MacroPurposeDomainSpec {
				// PTR lookup 自体で 1 term 消費
				if res := incrementDNSMechanismCounter(SPFResolver(d)); res != nil {
					return "", fmt.Errorf(res.Reason)
				}
			}

			// PTRルックアップ
			ptrRecords, res := d.lookupPTR(ctx.IP.String())
			if res != nil && res.Status != Pass {
				// PTRルックアップが失敗した場合は、元の実装に従って「unknown」を使用する
				ptr = "unknown"
			} else if len(ptrRecords) > 0 {
				// pyspf suite / RFC 7208 safety: process at most 10 PTR names.
				if len(ptrRecords) > 10 {
					ptrRecords = ptrRecords[:10]
				}

				// PTR RR count is folded into the global 10-term DNS mechanism limit.
				// %{p} 側には "ptr" メカニズムの事前 1 term が存在しないため、
				// ptrRecords の残り分 (len-1) を追加で消費します。
				if purpose == MacroPurposeDomainSpec {
					for i := 0; i < len(ptrRecords)-1; i++ {
						if res := incrementDNSMechanismCounter(SPFResolver(d)); res != nil {
							return "", fmt.Errorf(res.Reason)
						}
					}
				}

				// RFC 7208 7.3: p マクロは検証済みのドメイン名に展開される
				// 検証された最初のPTRレコードを使用する
				for _, ptrRecord := range ptrRecords {
					trimmedPTR := strings.TrimSuffix(ptrRecord, ".")
					// Validate PTR record by doing A/AAAA lookup
					ips, res2 := d.lookupIP(trimmedPTR)
					if res2 != nil {
						continue
					}
					if len(ips) > 10 {
						ips = ips[:10]
					}
					for _, ip := range ips {
						if ip.Equal(ctx.IP) {
							ptr = trimmedPTR
							break
						}
					}
					if ptr != "" {
						break
					}
				}
				// 検証済みのPTRレコードが見つからない場合は「unknown」を使用する
				if ptr == "" {
					ptr = "unknown"
				}
			} else {
				// PTRレコードが見つからない
				ptr = "unknown"
			}
			break
		}
	}

	// MacroClientPTRが含まれる場合は、PTRルックアップをする
	return replaceMacroTokens(tokens, ctx.Sender, ctx.Domain, ctx.Helo, ctx.Receiver, ctx.IP, ctx.Now.Unix(), ptr, purpose)
}

// expandDomainSpec は domain-spec を展開します。
func (d *dnsResolverImpl) expandDomainSpec(domainSpec string, ctx MacroContext, purpose MacroPurpose) (string, error) {
	expanded, result := expandDomainSpec(domainSpec, ctx, purpose)
	if result != nil && result.Status == PermError {
		return "", fmt.Errorf(result.Reason)
	}
	return expanded, nil
}

// expandDomainSpec は domain-spec を展開し、Result を返します。
func expandDomainSpec(domainSpec string, ctx MacroContext, purpose MacroPurpose) (string, *Result) {
	// 1) マクロ展開
	expanded, err := ctx.DNSResolver.ReplaceMacroValues(domainSpec, ctx, purpose)
	if err != nil {
		return "", &Result{Status: PermError, Reason: "macro expansion error: " + err.Error()}
	}

	// 2) SPF的に最低限の妥当性チェック（空とか末尾ドットとかは弾く）
	expanded = strings.TrimSpace(expanded)
	if expanded == "" {
		return "", &Result{Status: PermError, Reason: "empty domain-spec after macro expansion"}
	}
	// ここは厳密にやるならさらに: ラベル長/全体長/許容文字など
	// 最低でも " " や制御文字を含むなら弾く、くらいはおすすめです。

	// RFC 7208 8.1: マクロ展開後のドメイン名が253文字を超える場合は左側を切り捨てる
	if len(expanded) > 253 {
		labels := strings.Split(expanded, ".")
		// 右側のラベルを保持するように修正
		for len(strings.Join(labels, ".")) > 253 {
			if len(labels) <= 1 {
				// すべてのラベルを削除しても253文字を超える場合は、最後の253文字を返す
				expanded = expanded[len(expanded)-253:]
				break
			}
			// 左側のラベルを削除
			labels = labels[1:]
		}
		expanded = strings.Join(labels, ".")
	}

	return expanded, nil
}

type MacroContext struct {
	IP          net.IP
	Domain      string // check_host の current-domain
	Sender      string // MAIL FROM
	Helo        string // HELO/EHLO (持ってないなら追加推奨)
	Rcpt        string // receiver (exp 用 r のため。持ってないなら固定でも可)
	Receiver    string // receiver (rマクロ用)
	Now         time.Time
	DNSResolver DNSResolver
}

type MacroPurpose int

const (
	MacroPurposeDomainSpec MacroPurpose = iota // include/redirect/a/mx/ptr/exists など
	MacroPurposeExp                            // exp= のみ（c/r/t許可など）
)

type Macro rune

const (
	MacroSender         Macro = 's'
	MacroLocalPart      Macro = 'l'
	MacroDomainPart     Macro = 'o'
	MacroCurrentDomain  Macro = 'd'
	MacroClientIP       Macro = 'i'
	MacroClientPTR      Macro = 'p'
	MacroIPVersion      Macro = 'v'
	MacroHELODomain     Macro = 'h'
	MacroClientInfo     Macro = 'c'
	MacroReceiverDomain Macro = 'r'
	MacroTimestamp      Macro = 't'
)

func isMacroChar(x rune) bool {
	switch Macro(unicode.ToLower(x)) {
	case MacroSender, MacroLocalPart, MacroDomainPart, MacroCurrentDomain,
		MacroClientIP, MacroClientPTR, MacroIPVersion,
		MacroHELODomain, MacroClientInfo, MacroReceiverDomain,
		MacroTimestamp:
		return true
	}
	return false
}

func isMacroDelimiter(x rune) bool {
	switch x {
	case '.', '-', '_', '/', '=', '+', ',':
		return true
	}
	return false
}

func urlEscapeSPF(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// RFC 3986 予約されていない文字 = 英数字 / "-" / "." / "_" / "~"
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return b.String()
}

type TokenKind int

const (
	TokenLiteral TokenKind = iota
	TokenMacro
)

type Token struct {
	Kind  TokenKind
	Lit   string    // when Kind == TokenLiteral
	Macro MacroExpr // when Kind == TokenMacro
}

type MacroExpr struct {
	Letter  rune   // e.g. 'd', 'i', ...
	Num     int    // optional: keep right-most Num labels (0 means "unspecified")
	Reverse bool   // optional: 'r'
	Delims  string // optional: allowed delimiters, default "."
}

// RFC 7208に従ってマクロ文字列を解析します (%{...}、および%%、%_、%-のみ)
func parseMacroString(s string) ([]Token, error) {
	rs := []rune(s)
	n := len(rs)
	var out []Token

	i := 0
	for i < n {
		if rs[i] != '%' {
			// accumulate literal
			start := i
			for i < n && rs[i] != '%' {
				i++
			}
			out = append(out, Token{Kind: TokenLiteral, Lit: string(rs[start:i])})
			continue
		}

		// we have '%'
		if i+1 >= n {
			return nil, fmt.Errorf("dangling %% at end")
		}
		switch rs[i+1] {
		case '%': // %%
			out = append(out, Token{Kind: TokenLiteral, Lit: "%"})
			i += 2
			continue
		case '_': // %_ -> space
			out = append(out, Token{Kind: TokenLiteral, Lit: " "})
			i += 2
			continue
		case '-': // %- -> "%20"
			out = append(out, Token{Kind: TokenLiteral, Lit: "%20"})
			i += 2
			continue
		case '{':
			// %{ ... }
			j := i + 2
			// need: <letter>[<num>]['r'][<delims>]}
			if j >= n {
				return nil, fmt.Errorf("incomplete macro after %%{")
			}
			if !isMacroChar(rs[j]) {
				return nil, fmt.Errorf("invalid macro letter %q at %d", rs[j], j)
			}
			me := MacroExpr{Letter: rs[j]}
			j++

			// optional <num>
			numStart := j
			for j < n && unicode.IsDigit(rs[j]) {
				j++
			}
			if j > numStart {
				var num int
				for k := numStart; k < j; k++ {
					num = num*10 + int(rs[k]-'0')
				}
				// DIGIT変換で0が指定された場合はエラーとする
				if num == 0 {
					return nil, fmt.Errorf("DIGIT transformer must be non-zero")
				}
				me.Num = num
			}

			// optional 'r'
			if j < n && rs[j] == 'r' {
				me.Reverse = true
				j++
			}

			// optional delimiter set until '}'
			dStart := j
			for j < n && rs[j] != '}' {
				if !isMacroDelimiter(rs[j]) {
					return nil, fmt.Errorf("invalid delimiter %q in macro at %d", rs[j], j)
				}
				j++
			}
			if j >= n || rs[j] != '}' {
				return nil, fmt.Errorf("macro not closed with } starting at %d", i)
			}
			if j > dStart {
				me.Delims = string(rs[dStart:j])
			} else {
				me.Delims = "." // default
			}

			out = append(out, Token{Kind: TokenMacro, Macro: me})
			i = j + 1
			continue

		default:
			// RFCでは %<letter> 形式は定義されていない。互換目的で許さないほうが安全。
			return nil, fmt.Errorf("サポートされていないエスケープ '%%%c' (%%{...}を使用してください)", rs[i+1])
		}
	}
	return out, nil
}

func replaceMacroTokens(tokens []Token, sender, domain, helo, receiver string, ip net.IP, timestamp int64, ptr string, purpose MacroPurpose) (string, error) {
	var sb strings.Builder

	for _, tok := range tokens {
		switch tok.Kind {
		case TokenLiteral:
			sb.WriteString(tok.Lit)
		case TokenMacro:
			val, err := expandMacro(tok.Macro, sender, domain, helo, receiver, ip, timestamp, ptr, purpose)
			if err != nil {
				return "", err
			}
			sb.WriteString(val)
		}
	}
	return sb.String(), nil
}

func macroClientI(ip net.IP) string {
	if ip == nil {
		return ""
	}

	// For both IPv4 and IPv6, return the standard format
	// Reversal is handled by the 'r' transformer in expandMacro
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}

	if ip16 := ip.To16(); ip16 != nil {
		// For IPv6, generate nibble format (dot-separated hex digits)
		// RFC 7208 requires uppercase hex digits for macro expansions
		parts := make([]string, 32)
		for i := 0; i < 16; i++ {
			parts[i*2] = fmt.Sprintf("%X", (ip16[i]&0xF0)>>4)
			parts[i*2+1] = fmt.Sprintf("%X", ip16[i]&0x0F)
		}
		return strings.Join(parts, ".")
	}

	return ""
}

func expandMacro(me MacroExpr, sender, domain, helo, receiver string, ip net.IP, timestamp int64, ptr string, purpose MacroPurpose) (string, error) {
	lower := unicode.ToLower(me.Letter)
	if (lower == rune(MacroClientInfo) || lower == rune(MacroReceiverDomain) || lower == rune(MacroTimestamp)) && purpose == MacroPurposeDomainSpec {
		return "", fmt.Errorf("macro %%%c only allowed in exp=", me.Letter)
	}
	var raw string
	switch Macro(lower) {
	case MacroSender:
		raw = sender
	case MacroLocalPart:
		at := strings.Index(sender, "@")
		if at >= 0 {
			raw = sender[:at]
		} else {
			raw = sender
		}
	case MacroDomainPart:
		at := strings.Index(sender, "@")
		if at >= 0 {
			raw = sender[at+1:]
		} else {
			raw = domain
		}
	case MacroCurrentDomain:
		raw = domain
	case MacroClientIP:
		raw = macroClientI(ip)
	case MacroClientPTR:
		raw = ptr
	case MacroIPVersion:
		if ip.To4() != nil {
			// For IPv4, return "in-addr"
			raw = "in-addr"
		} else {
			// For IPv6, return "ip6"
			raw = "ip6"
		}
	case MacroHELODomain:
		raw = helo
	case MacroClientInfo:
		raw = ip.String()
	case MacroReceiverDomain:
		raw = receiver
	case MacroTimestamp:
		raw = fmt.Sprintf("%d", timestamp)
	default:
		return "", fmt.Errorf("unknown macro letter: %c", me.Letter)
	}

	// 分割
	var labels []string
	if lower == 'i' {
		// For 'i' macro, no splitting is done by default
		// But if 'r' is specified, we need to handle reversal differently based on IP version
		if me.Reverse {
			// For 'ir' macro, handle reversal based on IP version
			if ip.To4() != nil {
				// For IPv4, reverse the octets
				parts := strings.Split(raw, ".")
				for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
					parts[i], parts[j] = parts[j], parts[i]
				}
				labels = parts
			} else if ip.To16() != nil {
				// For IPv6, the raw value is already in nibble format, just split it
				labels = strings.Split(raw, ".")
				// Then reverse the nibbles
				for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
					labels[i], labels[j] = labels[j], labels[i]
				}
			} else {
				labels = []string{raw}
			}
		} else {
			// No reversal, just use raw value
			labels = []string{raw}
		}
	} else if lower == 'c' {
		// For 'c' macro, use the IP in its standard representation
		if ip.To4() != nil {
			// For IPv4, split on '.'
			labels = strings.Split(raw, ".")
		} else if ip.To16() != nil {
			// For IPv6, use the standard lowercase representation
			labels = []string{ip.String()}
		} else {
			labels = []string{raw}
		}
	} else if me.Delims != "." && me.Delims != "" {
		// Delimsを使ってsplit - 複数の区切り文字をサポート
		// Split on any of the delimiter characters
		labels = []string{raw}
		for _, delim := range me.Delims {
			var newLabels []string
			for _, label := range labels {
				newLabels = append(newLabels, strings.Split(label, string(delim))...)
			}
			labels = newLabels
		}
	} else {
		// cの処理をRFCに準拠するように修正
		if lower == 'c' && me.Delims == "" {
			// delimiter指定がなければ'.' splitが基本
			labels = strings.Split(raw, ".")
		} else {
			labels = strings.Split(raw, ".")
		}
	}

	// Handle reversal for non-'i' macros
	if me.Reverse && lower != 'i' {
		for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
			labels[i], labels[j] = labels[j], labels[i]
		}
	}

	// 右端から Num 個を取得
	if me.Num > 0 && me.Num < len(labels) {
		labels = labels[len(labels)-me.Num:]
	}

	// 再結合
	out := strings.Join(labels, ".")
	if unicode.IsUpper(me.Letter) {
		out = urlEscapeSPF(out)
	}
	return out, nil
}
