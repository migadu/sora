package lookupcache

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

// digestKey is a process-random HMAC key used for every PasswordDigest in this
// process. It is generated at startup, never persisted, and never logged.
//
// Together with the per-digest salt it means a digest is only meaningful to the
// process that produced it: a digest that escapes the cache (a log line, a
// serialized dump, a partially-disclosed heap page) cannot be attacked with
// precomputed tables, and two processes never agree on the digest of the same
// password.
var digestKey = newDigestKey()

func newDigestKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failing is unrecoverable: without it the digests below
		// would fall back to a predictable key, which is precisely what this
		// type exists to avoid.
		panic("lookupcache: failed to generate password digest key: " + err.Error())
	}
	return key
}

// PasswordDigest is a keyed, salted, constant-time-comparable digest of a
// plaintext password.
//
// It answers exactly one question: "was this cache entry created with the same
// password the client just presented?" It is NOT a credential store and is
// never used to authenticate on its own — the entry's HashedPassword (bcrypt /
// SSHA512, from the database or remote lookup) remains the authority for
// backends, and proxies use this only to decide whether a previously verified
// entry still applies.
//
// It replaces the unsalted SHA-256 of the plaintext password that used to be
// held here. That digest was directly attackable with rainbow tables and made
// password reuse across accounts visible at a glance; both are precomputation
// attacks that a per-digest random salt plus a process-random key defeat.
// Verification stays a single SHA-256, so the cache's whole reason for existing
// (absorbing reconnect storms without a bcrypt or a database round trip per
// login) is unaffected.
type PasswordDigest struct {
	salt [16]byte
	mac  [32]byte
	set  bool
}

// NewPasswordDigest derives a digest of password with a fresh random salt.
// An empty password yields the zero digest, which never matches anything.
func NewPasswordDigest(password string) PasswordDigest {
	if password == "" {
		return PasswordDigest{}
	}

	var d PasswordDigest
	if _, err := rand.Read(d.salt[:]); err != nil {
		panic("lookupcache: failed to generate password digest salt: " + err.Error())
	}
	d.mac = computeDigest(d.salt, password)
	d.set = true
	return d
}

// IsSet reports whether the digest was derived from a non-empty password.
func (d PasswordDigest) IsSet() bool {
	return d.set
}

// Matches reports whether password produces this digest. The comparison is
// constant-time so a cache hit never leaks how much of the digest matched.
// An unset digest and an empty password both match nothing.
func (d PasswordDigest) Matches(password string) bool {
	if !d.set || password == "" {
		return false
	}
	candidate := computeDigest(d.salt, password)
	return subtle.ConstantTimeCompare(d.mac[:], candidate[:]) == 1
}

func computeDigest(salt [16]byte, password string) [32]byte {
	mac := hmac.New(sha256.New, digestKey)
	mac.Write(salt[:])
	mac.Write([]byte(password))

	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}
