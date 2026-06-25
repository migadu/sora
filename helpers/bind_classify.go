package helpers

import (
	"net"
	"strings"
)

// BindIsPubliclyReachable reports whether a server bound to listenAddr could accept
// connections from a public (globally-routable) network. It exists so callers can warn
// about a dangerous misconfiguration — plaintext authentication allowed without TLS on a
// publicly reachable listener — WITHOUT crying wolf on the normal deployment where
// backends bind a private address (or a wildcard on a private-only host) behind a
// TLS-terminating proxy.
//
// Classification:
//   - A specific IP bind is judged directly: loopback / private (RFC1918, ULA) /
//     link-local / CGNAT → not public; any other global-unicast address → public.
//   - A wildcard / unspecified bind (":143", "0.0.0.0:143", "[::]:143") is public only
//     if the host actually has at least one globally-routable interface address.
//   - A hostname (non-IP) bind, or anything that cannot be parsed, returns false
//     (fail quiet: do not warn when we cannot be sure).
func BindIsPubliclyReachable(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// listenAddr may have no port; treat the whole value as the host.
		host = listenAddr
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))

	// Wildcard / unspecified bind: classify by the host's real interface addresses.
	if host == "" || host == "0.0.0.0" || host == "::" {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return false
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && isPublicIP(ipnet.IP) {
				return true
			}
		}
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname bind — cannot classify reliably; stay quiet.
		return false
	}
	return isPublicIP(ip)
}

// isPublicIP reports whether ip is a globally-routable unicast address — excluding
// loopback, RFC1918/ULA private, link-local, and RFC6598 CGNAT (100.64.0.0/10) ranges.
// Note: net.IP.IsGlobalUnicast returns true even for private ranges, so the private/
// loopback/link-local checks below are required.
func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// RFC 6598 carrier-grade NAT space (100.64.0.0/10) is not publicly routable.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}
