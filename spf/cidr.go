package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// value が "example.com/24//64" や "/24"（ドメイン省略）等を取り得る前提で分解
func splitHostAndDualCIDR(s string) (host string, v4bits, v6bits int, err error) {
	host = s
	v4bits, v6bits = -1, -1
	if s == "" {
		return "", -1, -1, nil
	}

	// 特殊なケース: コロンを含むドメイン名 (例: foo:bar/baz.example.com)
	// この場合、CIDRは存在しないと仮定する
	// 最初のコロンの位置を検索
	firstColon := strings.Index(s, ":")
	if firstColon != -1 {
		// 最後のスラッシュの位置を検索
		lastSlash := strings.LastIndex(s, "/")
		// コロンがスラッシュよりも前にある場合、これはCIDRではないと仮定
		// 例: foo:bar/baz.example.com -> ドメイン全体がホスト、CIDRなし
		// ただし、lastSlashが存在し、かつfirstColon < lastSlashであっても、
		// 実際にCIDRとして解釈できるかを確認する
		if lastSlash != -1 && firstColon < lastSlash {
			// foo:bar/baz.example.com のようなケース
			// CIDR部分を抽出 (baz.example.com)
			cidrCandidate := s[lastSlash+1:]
			// CIDR部分が数字のみで構成されているかを確認
			if _, parseErr := strconv.Atoi(cidrCandidate); parseErr != nil {
				// 数字でない場合はCIDRではないと判断し、ホスト全体を返す
				host = s
				return host, v4bits, v6bits, nil
			}
			// 数字の場合は、通常のCIDR解析を続行
		} else {
			// CIDRなしとして扱う
			host = s
			return host, v4bits, v6bits, nil
		}
	}

	// 最後の "//" で分割して、ホスト部とCIDR部を分離
	// これにより、"example.com//64" のようなケースを正しく処理できる
	parts := strings.Split(s, "//")
	if len(parts) > 2 {
		// "//" が2つ以上ある場合は不正な形式
		return "", -1, -1, fmt.Errorf("invalid dual CIDR format")
	}

	// ホスト部とCIDR部を初期化
	hostPart := s
	cidrPart := ""

	// "//" で分割された場合の処理
	if len(parts) == 2 {
		hostPart = parts[0]
		cidrPart = parts[1]

		// CIDR部が空の場合は不正な形式
		if cidrPart == "" {
			return "", -1, -1, fmt.Errorf("invalid dual CIDR format: missing IPv6 CIDR")
		}

		// IPv6 CIDRの解析
		// Check for leading zeros in IPv6 CIDR
		if len(cidrPart) > 1 && cidrPart[0] == '0' {
			return "", -1, -1, fmt.Errorf("bad ipv6 bits: %q (leading zeros not allowed)", cidrPart)
		}

		n, e := strconv.Atoi(cidrPart)
		if e != nil || n < 0 || n > 128 {
			return "", -1, -1, fmt.Errorf("bad ipv6 bits: %q", cidrPart)
		}
		v6bits = n
	}

	// ホスト部に "/" がある場合、IPv4 CIDRも存在する可能性がある
	lastSlash := strings.LastIndex(hostPart, "/")
	if lastSlash == -1 {
		// "/" がない場合はホスト部のみ
		host = hostPart
		return host, v4bits, v6bits, nil
	}

	// ホスト部とIPv4 CIDR部に分割
	host = hostPart[:lastSlash]
	v4cidr := hostPart[lastSlash+1:]

	// IPv4 CIDR部が空の場合は不正な形式
	if v4cidr == "" {
		return "", -1, -1, fmt.Errorf("invalid dual CIDR format: missing IPv4 CIDR")
	}

	// IPv4 CIDRの解析
	// Check for leading zeros in IPv4 CIDR
	if len(v4cidr) > 1 && v4cidr[0] == '0' {
		return "", -1, -1, fmt.Errorf("bad ipv4 bits: %q (leading zeros not allowed)", v4cidr)
	}

	n, e := strconv.Atoi(v4cidr)
	if e != nil || n < 0 || n > 32 {
		return "", -1, -1, fmt.Errorf("bad ipv4 bits: %q", v4cidr)
	}
	v4bits = n
	return host, v4bits, v6bits, nil
}

// "1.2.3.4" または "1.2.3.0/24" / IPv6 も受け付ける。mask 省略時は /32 または /128。
func parseCIDRDefault(s string, wantV4 bool) (net.IP, *net.IPNet, error) {
	if strings.Contains(s, "/") {
		parts := strings.Split(s, "/")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid CIDR format")
		}
		// Check for leading zeros in CIDR mask
		mask := parts[1]
		if len(mask) > 1 && mask[0] == '0' {
			return nil, nil, fmt.Errorf("invalid CIDR mask: %q (leading zeros not allowed)", mask)
		}
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil, err
		}
		if wantV4 && ip.To4() == nil {
			return nil, nil, fmt.Errorf("expected IPv4")
		}
		if !wantV4 && ip.To4() != nil {
			// IPv4-mapped IPv6 address は IPv6 ネットワークとして扱う
			// net.ParseCIDR は既に正しい IPNet を返しているはず
			return ip, ipnet, nil
		}
		return ip, ipnet, nil
	}
	// CIDR形式でない場合、IPv4-mapped IPv6アドレスかどうかをチェックします
	// For non-CIDR format, check if it's an IPv4-mapped IPv6 address
	if strings.Contains(s, ":") && strings.Contains(s, ".") {
		// This is likely an IPv4-mapped IPv6 address, which should not be accepted for wantV4=true
		if wantV4 {
			return nil, nil, fmt.Errorf("not an IPv4 address")
		}
		// For wantV4=false, IPv4-mapped IPv6 addresses are valid IPv6 addresses
		// and should be accepted for ip6 mechanism
		if !wantV4 {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid ip %q", s)
			}
			// IPv4-mapped IPv6 address は IPv6 アドレスとして扱う
			return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
		}
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid ip %q", s)
	}
	if wantV4 && ip.To4() == nil {
		return nil, nil, fmt.Errorf("expected IPv4")
	}
	if !wantV4 && ip.To4() != nil {
		// IPv4アドレスがIPv6メカニズムで使用された場合、これはIPv4-mapped IPv6アドレスとして扱われることもある
		// しかし、RFC 4408/7208 では、IPv4-mapped IPv6アドレスはIPv6メカニズムでは使用できない
		// ただし、純粋なIPv4アドレスはIPv6メカニズムでは無効
		// ただし、net.ParseIPはIPv4アドレスをIPv4-mapped IPv6アドレスに変換する可能性がある
		// そのため、wantV4=falseの場合はエラーとする
		return nil, nil, fmt.Errorf("expected IPv6")
	}
	var bits int
	if wantV4 {
		bits = 32
	} else {
		bits = 128
	}
	return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

func dualCIDRMatch(src net.IP, dst net.IP, v4bits, v6bits int) bool {
	if src == nil || dst == nil {
		return false
	}
	// IPv4 connection
	if src.To4() != nil {
		// For IPv4 connection, we only use v4bits
		bits := 32
		if v4bits >= 0 {
			if v4bits > 32 {
				return false
			}
			bits = v4bits
		}
		// If dst is IPv4, compare directly
		if dst.To4() != nil {
			return src.Mask(net.CIDRMask(bits, 32)).Equal(dst.Mask(net.CIDRMask(bits, 32)))
		}
		// If dst is IPv4-mapped IPv6, convert it to IPv4 and compare
		if ip4 := dst.To4(); ip4 != nil {
			return src.Mask(net.CIDRMask(bits, 32)).Equal(ip4.Mask(net.CIDRMask(bits, 32)))
		}
		// dst is pure IPv6, no match for IPv4 connection
		// This is the key fix: when src is IPv4 and dst is IPv6, it should not match
		// regardless of v6bits value
		return false
	}
	// IPv6 connection
	if src.To4() == nil {
		// For IPv6 connection, we only use v6bits
		bits := 128
		if v6bits >= 0 {
			if v6bits > 128 {
				return false
			}
			bits = v6bits
		}
		// If dst is IPv6, compare directly
		if dst.To4() == nil {
			return src.Mask(net.CIDRMask(bits, 128)).Equal(dst.Mask(net.CIDRMask(bits, 128)))
		}
		// If dst is IPv4-mapped IPv6, convert src to IPv4 and compare
		// But only if we're doing IPv4-style matching (which we're not in this branch)
		// For IPv6 connection with IPv4-mapped address, we should still use IPv6 CIDR
		// This is consistent with RFC 4408/7208
		return false
	}
	// Should not reach here
	return false
}
