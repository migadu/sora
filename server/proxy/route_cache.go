package proxy

import (
	"crypto/subtle"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
)

// CacheRoute records a lookup answer's route in a lookup-cache entry: the pin or the pool,
// every backend-leg setting the answer carried, and whether the remote lookup gave it. The
// caller fills in what is not routing (password digest, resolved address, result).
//
// It and RouteFromCache are the one translation between the two, for every proxy: a login
// served from the cache must route exactly as the uncached login it was cached from, and a
// field copied by hand at one site and forgotten at another (IMAP and POP3 once dropped the
// pin's enforcement, POP3 its XCLIENT and UTF8 settings) silently changes that.
func CacheRoute(entry *lookupcache.CacheEntry, info *UserRoutingInfo) {
	entry.AccountID = info.AccountID
	entry.ServerAddress = info.ServerAddress
	entry.PoolName = info.PoolName
	entry.RemoteTLS = info.RemoteTLS
	entry.RemoteTLSUseStartTLS = info.RemoteTLSUseStartTLS
	entry.RemoteTLSVerify = info.RemoteTLSVerify
	entry.RemoteUseProxyProtocol = info.RemoteUseProxyProtocol
	entry.RemoteUseIDCommand = info.RemoteUseIDCommand
	entry.RemoteSkipForwardingWithProxyProtocol = info.RemoteSkipForwardingWithProxyProtocol
	entry.RemoteUseXCLIENT = info.RemoteUseXCLIENT
	entry.RemoteUseUTF8 = info.RemoteUseUTF8
	entry.FromRemoteLookup = info.IsRemoteLookupAccount
}

// RouteFromCache rebuilds the routing info a cached entry was made from (see CacheRoute).
// A lookup answer without a server, a pool answer or an auth-only one, is auth-only mode,
// as the lookup client reports it; a pin keeps its enforcement (IsRemoteLookupAccount).
func RouteFromCache(entry *lookupcache.CacheEntry) *UserRoutingInfo {
	return &UserRoutingInfo{
		AccountID:                             entry.AccountID,
		ServerAddress:                         entry.ServerAddress,
		PoolName:                              entry.PoolName,
		IsRemoteLookupAccount:                 entry.FromRemoteLookup,
		AuthOnlyMode:                          entry.FromRemoteLookup && entry.ServerAddress == "",
		RemoteTLS:                             entry.RemoteTLS,
		RemoteTLSUseStartTLS:                  entry.RemoteTLSUseStartTLS,
		RemoteTLSVerify:                       entry.RemoteTLSVerify,
		RemoteUseProxyProtocol:                entry.RemoteUseProxyProtocol,
		RemoteUseIDCommand:                    entry.RemoteUseIDCommand,
		RemoteSkipForwardingWithProxyProtocol: entry.RemoteSkipForwardingWithProxyProtocol,
		RemoteUseXCLIENT:                      entry.RemoteUseXCLIENT,
		RemoteUseUTF8:                         entry.RemoteUseUTF8,
	}
}

// MasterFormOtherCredential reports whether password and the password a positive
// lookup-cache entry for username was made with are the two credentials of the master
// username form "user@domain.com@MASTERUSER": one is the master password, the other is
// not. Both log in under that name (#949), the master password as a master login and any
// other password as the account's own login, and they share its one cache entry. A fresh
// positive entry refuses any other password as a wrong one, so either login refused the
// other until the entry aged past the revalidation window; the proxies check such a pair
// again instead. One side is always the master password, so after the account's own
// login a client without it is answered exactly as under another suffix. Both
// comparisons run whatever the suffix.
func MasterFormOtherCredential(username, password string, cached lookupcache.PasswordDigest, masterUsername, masterPassword []byte) bool {
	if len(masterUsername) == 0 || len(masterPassword) == 0 {
		return false
	}
	addr, err := server.NewAddress(username)
	masterForm := err == nil && addr.HasSuffix() && subtle.ConstantTimeCompare([]byte(addr.Suffix()), masterUsername) == 1
	masterPresented := subtle.ConstantTimeCompare([]byte(password), masterPassword) == 1
	masterCached := cached.Matches(string(masterPassword))
	return masterForm && masterPresented != masterCached
}
