package spf

import "net"

// CheckSPF performs an SPF check for the given IP, domain, sender, and HELO.
func CheckSPF(ip net.IP, domain, sender, helo string) *Result {
	resolver := newDNSResolver()
	return resolver.CheckSPF(ip, domain, sender, helo)
}
