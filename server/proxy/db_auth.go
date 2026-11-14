package proxy

import (
	"errors"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

// IsTemporaryDBAuthFailure reports whether an error from
// ResilientDatabase.AuthenticateWithRetry gives no verdict on the submitted password,
// so the IMAP, POP3 and ManageSieve proxies answer it as a temporary failure and
// neither count it as a failed login nor cache it: the database could not be asked
// (server.IsTemporaryAuthFailure), or the stored hash cannot be checked
// (db.ErrUnverifiableHash). The second is a fault in the stored data that only an
// administrator can repair, as a lookup answer carrying such a hash is a fault in the
// lookup service (ErrRemoteLookupInvalidResponse); a rate-limit block earned on it
// would outlast the repair.
func IsTemporaryDBAuthFailure(err error) bool {
	return server.IsTemporaryAuthFailure(err) || errors.Is(err, db.ErrUnverifiableHash)
}

// ClassifyDBAuthFailure classifies an error from ResilientDatabase.AuthenticateWithRetry
// for the IMAP, POP3 and ManageSieve proxies' main-database login. It returns the reason
// they log ("user_not_found", "invalid_password", "unverifiable_hash" or
// "transient_error") and whether the failure is definitive, i.e. may be cached as a
// negative lookup-cache entry.
//
// Only an unknown address and a wrong password (for every hash scheme) are definitive.
// A stored hash that cannot be checked says nothing about the password and is fixed by
// an administrator, so it is not cached either (IsTemporaryDBAuthFailure). Anything
// else (database unreachable, a timeout) is never cached: the circuit breaker handles
// it and the next login asks again.
func ClassifyDBAuthFailure(err error) (reason string, definitive bool) {
	switch {
	case errors.Is(err, consts.ErrUserNotFound):
		return "user_not_found", true
	case errors.Is(err, db.ErrInvalidCredentials):
		return "invalid_password", true
	case errors.Is(err, db.ErrUnverifiableHash):
		return "unverifiable_hash", false
	default:
		return "transient_error", false
	}
}
