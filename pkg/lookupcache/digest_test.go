package lookupcache

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestPasswordDigest_Matches covers the one behaviour the cache depends on:
// a digest recognises the password it was built from and nothing else.
func TestPasswordDigest_Matches(t *testing.T) {
	d := NewPasswordDigest("testpass123")

	if !d.IsSet() {
		t.Fatal("digest of a non-empty password should be set")
	}
	if !d.Matches("testpass123") {
		t.Error("digest should match the password it was derived from")
	}
	if d.Matches("testpass124") {
		t.Error("digest should not match a different password")
	}
	if d.Matches("") {
		t.Error("digest should never match the empty password")
	}

	// Unicode passwords are hashed byte-wise like any other.
	u := NewPasswordDigest("пароль中文🔐")
	if !u.Matches("пароль中文🔐") {
		t.Error("digest should match a unicode password")
	}
	if u.Matches("пароль中文") {
		t.Error("digest should not match a truncated unicode password")
	}
}

// TestPasswordDigest_EmptyPassword pins the zero-digest behaviour the callers
// rely on: proxies build entries for master-auth logins that carry no password,
// and such an entry must never satisfy a later login.
func TestPasswordDigest_EmptyPassword(t *testing.T) {
	d := NewPasswordDigest("")

	if d.IsSet() {
		t.Error("digest of an empty password should not be set")
	}
	if d.Matches("") || d.Matches("anything") {
		t.Error("unset digest should match nothing")
	}

	// The zero value (a CacheEntry built without a digest) behaves the same.
	var zero PasswordDigest
	if zero.IsSet() || zero.Matches("anything") {
		t.Error("zero digest should be unset and match nothing")
	}
}

// TestPasswordDigest_IsSalted is the security regression guard. The cache used
// to hold an unsalted SHA-256 of the plaintext password, which made every entry
// attackable with a precomputed table and made two accounts sharing a password
// visible by comparing the two cached values. Both properties must stay gone.
func TestPasswordDigest_IsSalted(t *testing.T) {
	const password = "correct horse battery staple"

	a := NewPasswordDigest(password)
	b := NewPasswordDigest(password)

	if a.salt == b.salt {
		t.Error("two digests of the same password must not share a salt")
	}
	if a.mac == b.mac {
		t.Error("two digests of the same password must not be byte-identical (password reuse would be visible in a memory dump)")
	}
	// Each still matches its own password - the salt is carried with the digest.
	if !a.Matches(password) || !b.Matches(password) {
		t.Error("salted digests must still match their own password")
	}

	// And no digest is a plain hash of the password, with or without the salt.
	plain := sha256.Sum256([]byte(password))
	if bytes.Equal(a.mac[:], plain[:]) {
		t.Error("digest must not be an unsalted SHA-256 of the password")
	}
	salted := sha256.Sum256(append(a.salt[:], password...))
	if bytes.Equal(a.mac[:], salted[:]) {
		t.Error("digest must be keyed, not just salted")
	}
}

// TestPasswordDigest_KeyIsProcessRandom verifies the process key actually
// participates: recomputing a digest under a different key must not reproduce
// it, so a digest that escapes this process is not checkable elsewhere.
func TestPasswordDigest_KeyIsProcessRandom(t *testing.T) {
	const password = "hunter2"

	d := NewPasswordDigest(password)
	under := computeDigest(d.salt, password)
	if under != d.mac {
		t.Fatal("computeDigest should be deterministic under the same key and salt")
	}

	original := digestKey
	t.Cleanup(func() { digestKey = original })
	digestKey = newDigestKey()

	if computeDigest(d.salt, password) == d.mac {
		t.Error("digest should not be reproducible under a different process key")
	}
	if bytes.Equal(digestKey, original) {
		t.Error("newDigestKey should produce a fresh random key")
	}
}
