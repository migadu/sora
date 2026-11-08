package proxy

import "github.com/migadu/sora/pkg/lookupcache"

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
	entry.RemoteUseXCLIENT = info.RemoteUseXCLIENT
	entry.RemoteUseUTF8 = info.RemoteUseUTF8
	entry.FromRemoteLookup = info.IsRemoteLookupAccount
}

// RouteFromCache rebuilds the routing info a cached entry was made from (see CacheRoute).
// A lookup answer without a server, a pool answer or an auth-only one, is auth-only mode,
// as the lookup client reports it; a pin keeps its enforcement (IsRemoteLookupAccount).
func RouteFromCache(entry *lookupcache.CacheEntry) *UserRoutingInfo {
	return &UserRoutingInfo{
		AccountID:              entry.AccountID,
		ServerAddress:          entry.ServerAddress,
		PoolName:               entry.PoolName,
		IsRemoteLookupAccount:  entry.FromRemoteLookup,
		AuthOnlyMode:           entry.FromRemoteLookup && entry.ServerAddress == "",
		RemoteTLS:              entry.RemoteTLS,
		RemoteTLSUseStartTLS:   entry.RemoteTLSUseStartTLS,
		RemoteTLSVerify:        entry.RemoteTLSVerify,
		RemoteUseProxyProtocol: entry.RemoteUseProxyProtocol,
		RemoteUseIDCommand:     entry.RemoteUseIDCommand,
		RemoteUseXCLIENT:       entry.RemoteUseXCLIENT,
		RemoteUseUTF8:          entry.RemoteUseUTF8,
	}
}
