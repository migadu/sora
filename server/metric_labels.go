package server

import "strings"

// metricsProtocol returns the protocol label of the metrics of an auth rate limiter
// or connection tracker named name: the lowercase server type the other metrics use
// ("imap", "imap_proxy", "managesieve_proxy", "userapi", ...). A connection tracker
// of a proxy adds "_proxy" itself, since it has the protocol's name like a backend's.
//
// Only the label is mapped. The names stay as they are: they key the gossip between
// nodes, which must keep matching while a cluster runs mixed versions, and the
// tracker keys the Admin API parses.
func metricsProtocol(name string) string {
	switch name {
	case "IMAP-PROXY":
		return "imap_proxy"
	case "POP3-PROXY":
		return "pop3_proxy"
	case "SIEVE-PROXY":
		return "managesieve_proxy"
	case "user-api":
		return "userapi"
	case "USER-API-PROXY":
		return "userapi_proxy"
	}
	return strings.ToLower(name) // IMAP, POP3, ManageSieve, LMTP
}
