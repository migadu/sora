package server

import (
	"crypto/subtle"
	"strings"
)

// masterKeyNamespace prefixes the master credentials' rate-limiting keys. ":" is
// not a legal local-part character, so a namespaced key can never be produced by
// AuthRateLimitKey for a parseable address, and an unparseable identity that
// happens to collide only merges an attacker's own attempts into the master
// bucket — it can never clear it, since clearing needs a successful login under
// that identity and the identity does not parse.
const masterKeyNamespace = "master:"

// AuthRateLimitKey canonicalises a client-supplied authentication identity into
// the username key used for authentication rate limiting (Tier 1 is keyed on
// ip + "|" + username).
//
// The SAME key must be used at the CanAttemptAuth* check site and at every
// RecordAuthAttempt* site of a protocol. Checking under the raw client string
// while recording under the parsed address makes Tier 1 both bypassable (vary
// the case or append a different +detail on each attempt and no key ever
// repeats) and abusable (the resulting block lands on the victim's canonical
// address, locking a real user out).
//
// Identities that are not addresses — a master SASL username such as
// "proxyuser" — keep a stable key of their own rather than an empty one, which
// would merge every unparseable identity into a single shared bucket.
func AuthRateLimitKey(username string) string {
	if addr, err := NewAddress(username); err == nil {
		return addr.BaseAddress()
	}
	return strings.ToLower(strings.TrimSpace(username))
}

// MasterAuthRateLimitKey returns the key for an attempt that verifies a MASTER
// credential rather than an account's own password.
//
// It must never be derived from the impersonation target. The master forms name
// the account to act as, so keying on it charges an arbitrary account for an
// attempt that only mentioned it — a lockout primitive for anyone who can reach
// the port — and lets the caller vary the target to get a fresh Tier 1 bucket per
// guess, which stops the tenant-wide master password from being metered at all.
// The credential keeps ONE bucket of its own, which is what makes its
// brute-force accounting meaningful.
//
// masterID is the credential's own identifier: the master SASL username, or the
// suffix of a "user@domain.com@MASTERUSER" submission.
func MasterAuthRateLimitKey(masterID string) string {
	return masterKeyNamespace + strings.ToLower(strings.TrimSpace(masterID))
}

// AuthRateLimitKeyWithMaster is AuthRateLimitKey for the protocols that also
// accept the "user@domain.com@MASTERUSER" master form. That form canonicalises
// to the TARGET's address (see AuthRateLimitKey), which is precisely the key it
// must not use, so a submission whose suffix is the configured master username
// is keyed on the master credential instead.
//
// Deciding the key here — before the rate-limit check, from the raw submitted
// identity — is what keeps the check site and every RecordAuthAttempt* site of a
// protocol on the SAME key: recording a master attempt in one bucket while
// checking another would leave the master password unmetered.
func AuthRateLimitKeyWithMaster(username string, masterUsername []byte) string {
	if len(masterUsername) > 0 {
		// Constant-time, like every other comparison against a master
		// credential: the suffix is client-supplied.
		if addr, err := NewAddress(username); err == nil && addr.HasSuffix() &&
			subtle.ConstantTimeCompare([]byte(addr.Suffix()), masterUsername) == 1 {
			return MasterAuthRateLimitKey(addr.Suffix())
		}
	}
	return AuthRateLimitKey(username)
}
