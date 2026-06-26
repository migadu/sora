package helpers

import (
	"fmt"
	"net"
)

// ParseTrustedNetworks parses a slice of CIDR strings into a slice of *net.IPNet.
// Automatically adds /32 for IPv4 and /128 for IPv6 addresses without subnet notation, so a
// bare IP is accepted as a single-host network. This is the construction-time parser; its
// check-time counterpart is IPInNetworks, and the two MUST agree on bare-IP handling (see
// IPInNetworks for the bug that divergence caused).
func ParseTrustedNetworks(cidrs []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		// Try parsing as CIDR first
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// If CIDR parsing fails, try parsing as plain IP and add appropriate subnet
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted network '%s': not a valid IP address or CIDR", cidr)
			}

			// Determine if IPv4 or IPv6 and add appropriate subnet
			var cidrWithSubnet string
			if ip.To4() != nil {
				// IPv4 address
				cidrWithSubnet = cidr + "/32"
			} else {
				// IPv6 address
				cidrWithSubnet = cidr + "/128"
			}

			// Parse the corrected CIDR
			_, network, err = net.ParseCIDR(cidrWithSubnet)
			if err != nil {
				return nil, fmt.Errorf("failed to parse corrected CIDR '%s': %w", cidrWithSubnet, err)
			}
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// IPInNetworks reports whether ip falls within any entry of networks. Entries may be CIDRs
// ("10.0.0.0/8") OR bare IPs ("10.0.0.1", treated as /32 or /128). This is the single
// check-time counterpart to ParseTrustedNetworks (the construction-time parser): both accept
// bare IPs identically, so every trust check — XCLIENT advertisement vs command authorization,
// rate-limit exemptions, host allow-lists — agrees on the same list. The bug this prevents: a
// bare-IP entry that one path normalized to /32 while another (raw net.ParseCIDR) silently
// skipped, advertising XCLIENT but then denying it with "451 XCLIENT denied". A nil ip and
// unparseable entries are no-match (never fatal). Prefer pre-parsing with ParseTrustedNetworks
// and matching *net.IPNet on hot paths; use this when only the raw string list is available.
func IPInNetworks(ip net.IP, networks []string) bool {
	if ip == nil {
		return false
	}
	for _, entry := range networks {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			// Not CIDR notation — accept a bare IP as a single-host network.
			parsed := net.ParseIP(entry)
			if parsed == nil {
				continue
			}
			mask := "/32"
			if parsed.To4() == nil {
				mask = "/128"
			}
			if _, network, err = net.ParseCIDR(entry + mask); err != nil {
				continue
			}
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
