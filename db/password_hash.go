package db

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// A stored password is a bare bcrypt hash ($2a$, $2b$ or $2y$) or Dovecot's
// "{SCHEME}data" / "{SCHEME.ENCODING}data". As in Dovecot, the scheme name and the
// encoding are case-insensitive and the encoding is "b64", "base64" or "hex"
// (src/lib-auth/password-scheme.c: the scheme table is created with strcasecmp, and
// password_scheme_lookup compares the suffix with strcasecmp).

// parsedHash is a stored password split into the scheme it is verified with and the
// data that scheme compares against.
type parsedHash struct {
	scheme string // "ssha512", "sha512", "blf_crypt", "crypt" or "bcrypt", the metric label
	data   []byte // the digest (and salt) for ssha512 and sha512, a bcrypt hash otherwise
}

// otherDovecotSchemes are the Dovecot schemes sora does not verify
// (src/lib-auth/password-scheme.c, password-scheme-crypt.c, password-scheme-sodium.c,
// and OTP from 2.3). An error names one of these; any other {SCHEME} is not repeated,
// since it may be part of a password.
var otherDovecotSchemes = []string{
	"ARGON2", "ARGON2I", "ARGON2ID", "CLEAR", "CLEARTEXT", "CRAM-MD5", "DES-CRYPT",
	"DIGEST-MD5", "HMAC-MD5", "LDAP-MD5", "MD5", "MD5-CRYPT", "OTP", "PBKDF2", "PLAIN",
	"PLAIN-MD4", "PLAIN-MD5", "PLAIN-TRUNC", "SCRAM-SHA-1", "SCRAM-SHA-256", "SHA", "SHA1",
	"SHA256", "SHA256-CRYPT", "SHA512-CRYPT", "SMD5", "SSHA", "SSHA256",
}

const verifiedSchemes = "SSHA512, SHA512, BLF-CRYPT, CRYPT with a bcrypt hash, or a bare bcrypt hash"

func unverifiable(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnverifiableHash}, args...)...)
}

// ValidatePasswordHash checks that a pre-computed password hash is one VerifyPassword
// can check, so a credential is never stored that no password signs in to. It parses
// the value exactly as VerifyPassword does. The error wraps ErrUnverifiableHash.
func ValidatePasswordHash(hash string) error {
	_, err := parsePasswordHash(hash)
	return err
}

// parsePasswordHash parses a stored password the way VerifyPassword checks it. Every
// error wraps ErrUnverifiableHash and quotes no part of stored. The scheme is set
// whenever it is one sora verifies, also with an error.
func parsePasswordHash(stored string) (h parsedHash, err error) {
	if !strings.HasPrefix(stored, "{") {
		if !hasBcryptPrefix(stored) {
			return h, unverifiable("no {SCHEME} prefix and not a bcrypt hash: use %s", verifiedSchemes)
		}
		h.scheme, h.data = "bcrypt", []byte(stored)
		return h, checkBcrypt(h.data)
	}
	end := strings.IndexByte(stored, '}')
	if end < 0 {
		return h, unverifiable("no {SCHEME} prefix and not a bcrypt hash: use %s", verifiedSchemes)
	}
	name, suffix, hasSuffix := strings.Cut(stored[1:end], ".")
	data := stored[end+1:]

	name = upperASCII(name)
	encoding := "" // the scheme's default encoding: "" (none), "BASE64" or "HEX"
	rawLen := 0    // the decoded length when the scheme fixes it, Dovecot's raw_password_len
	switch name {
	case "SSHA512":
		h.scheme, encoding = "ssha512", "BASE64"
	case "SHA512":
		h.scheme, encoding, rawLen = "sha512", "BASE64", sha512.Size
	case "BLF-CRYPT":
		h.scheme = "blf_crypt"
	case "CRYPT":
		h.scheme = "crypt"
	default:
		if slices.Contains(otherDovecotSchemes, name) {
			return h, unverifiable("scheme %s is not supported: use %s", name, verifiedSchemes)
		}
		return h, unverifiable("unknown scheme: use %s", verifiedSchemes)
	}

	if hasSuffix {
		switch upperASCII(suffix) {
		case "B64", "BASE64":
			encoding = "BASE64"
		case "HEX":
			encoding = "HEX"
		default:
			return h, unverifiable("unknown encoding suffix: use .b64, .base64 or .hex")
		}
	}
	var raw []byte
	switch encoding {
	case "":
		raw = []byte(data)
	case "HEX":
		raw, err = hex.DecodeString(data)
	case "BASE64":
		// Without a suffix, a value twice a fixed length is hex, and base64 if it does
		// not decode as hex (Dovecot's password_decode).
		if !hasSuffix && rawLen != 0 && len(data) == 2*rawLen {
			if raw, err = hex.DecodeString(data); err == nil {
				break
			}
		}
		raw, err = base64.StdEncoding.DecodeString(data)
	}
	if err != nil {
		return h, unverifiable("%s data does not decode", name)
	}

	switch h.scheme {
	case "ssha512":
		if len(raw) <= sha512.Size {
			return h, unverifiable("SSHA512 data is %d bytes: want the %d-byte digest and a salt", len(raw), sha512.Size)
		}
	case "sha512":
		if len(raw) != sha512.Size {
			return h, unverifiable("SHA512 data is %d bytes, want %d", len(raw), sha512.Size)
		}
	case "crypt":
		// Dovecot's CRYPT is crypt(3). It generates bcrypt and verifies a $2?$ value
		// as BLF-CRYPT (password-scheme-crypt.c, crypt_verify); sora does not verify
		// the other crypt(3) algorithms (DES, MD5, SHA-256, SHA-512).
		if !hasBcryptPrefix(string(raw)) {
			return h, unverifiable("CRYPT is verified only for a bcrypt hash ($2a$, $2b$ or $2y$)")
		}
		fallthrough
	case "blf_crypt":
		if err := checkBcrypt(raw); err != nil {
			return h, err
		}
	}
	h.data = raw
	return h, nil
}

// hasBcryptPrefix reports whether s starts like a bcrypt hash of a variant Go's bcrypt
// verifies as written: $2a$, $2b$ or $2y$ (which differ only in bugs of other
// implementations; $2x$ is crypt_blowfish's bug-compatible variant, which Go computes
// as $2a$).
func hasBcryptPrefix(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

// bcryptHashLen is the length of a bcrypt hash: "$2a$", a two-digit cost, "$", a
// 22-character salt and a 31-character hash.
const bcryptHashLen = 60

// checkBcrypt checks that h is a bcrypt hash that bcrypt.CompareHashAndPassword can
// match. Go's bcrypt parses a value of another length, but it never matches.
func checkBcrypt(h []byte) error {
	if len(h) != bcryptHashLen || !hasBcryptPrefix(string(h)) || h[6] != '$' {
		return unverifiable("not a bcrypt hash: want $2a$, $2b$ or $2y$, a two-digit cost, $ and 53 characters of salt and hash")
	}
	if _, err := bcrypt.Cost(h); err != nil {
		return unverifiable("bcrypt cost is not a number from %d to %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	for _, c := range h[7:] {
		if !(c == '.' || c == '/' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return unverifiable("bcrypt salt and hash are not in bcrypt's base64 alphabet")
		}
	}
	return nil
}

// upperASCII upper-cases the ASCII letters of s only, as Dovecot's strcasecmp compares
// (strings.ToUpper also maps some non-ASCII letters to ASCII ones).
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
