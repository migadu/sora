package server

// LMTPAdmissionNetworks returns the networks an LMTP listener, the backend or
// lmtp_proxy, admits connections from: trusted_networks, or loopback and the RFC 1918
// ranges when it is empty. LMTP is internal-only, and the empty default that keeps
// PROXY/XCLIENT trust fail-closed must not reject all delivery. Trusting a peer to
// assert a client IP is a separate, explicit grant: it never gets this default.
func LMTPAdmissionNetworks(trustedNetworks []string) []string {
	if len(trustedNetworks) > 0 {
		return trustedNetworks
	}
	return []string{
		"127.0.0.0/8",    // localhost
		"::1/128",        // IPv6 localhost
		"10.0.0.0/8",     // RFC1918 private networks
		"172.16.0.0/12",  // RFC1918 private networks
		"192.168.0.0/16", // RFC1918 private networks
	}
}
