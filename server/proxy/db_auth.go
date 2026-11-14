package proxy

import (
	"errors"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// ClassifyDBAuthFailure classifies an error from ResilientDatabase.AuthenticateWithRetry
// for the IMAP, POP3 and ManageSieve proxies' main-database login. It returns the reason
// they log ("user_not_found", "invalid_password", "unverifiable_hash" or
// "transient_error") and whether the failure is definitive, i.e. may be cached as a
// negative lookup-cache entry.
//
// Only an unknown address and a wrong password (for every hash scheme) are definitive.
// A stored hash that cannot be checked says nothing about the password and is fixed by
// an administrator, so it is not cached either. Anything else (database unreachable, a
// timeout) is never cached: the circuit breaker handles it and the next login asks
// again.
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
