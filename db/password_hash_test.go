package db

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/bcrypt"
)

// sha512CryptOfSecret is a real Dovecot SHA512-CRYPT value (glibc crypt(3) "$6$") of
// "Secret-2026": a scheme Dovecot verifies and sora does not.
const sha512CryptOfSecret = "{SHA512-CRYPT}$6$saltsaltsaltsalt$Uz0B733KLAcpeAFT5hlALRwUMzwqxSoBO9VG7Ph8v7auZDaXL8PutBQPqOVLMvwy0rORlpwlXHm83Z4uAhgLB0"

// dovecotSpellings returns, for password, every way Dovecot writes a hash of a scheme
// sora verifies. Dovecot looks the scheme up case-insensitively and takes the encoding
// from a ".b64", ".base64" or ".hex" suffix, also case-insensitively
// (src/lib-auth/password-scheme.c: the scheme table is created with strcasecmp, and
// password_scheme_lookup compares the suffix with strcasecmp). A {SHA512} value
// without a suffix is hex when it is twice the digest length and base64 otherwise
// (password_decode). {CRYPT} generates bcrypt ($2y$) and hands a $2?$ value to
// BLF-CRYPT (password-scheme-crypt.c, crypt_verify).
func dovecotSpellings(t *testing.T, password string) []string {
	t.Helper()
	salt := []byte("saltsalt")
	ssha := sha512.Sum512(append([]byte(password), salt...))
	sshaRaw := append(ssha[:], salt...)
	sha := sha512.Sum512([]byte(password))
	bc, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	bc2y := "$2y$" + string(bc[4:]) // what Dovecot's BLF-CRYPT and CRYPT generate
	b64 := base64.StdEncoding.EncodeToString

	return []string{
		"{ssha512}" + b64(sshaRaw),
		"{Ssha512}" + b64(sshaRaw),
		"{SSHA512.hex}" + hex.EncodeToString(sshaRaw),
		"{SSHA512.Hex}" + strings.ToUpper(hex.EncodeToString(sshaRaw)),
		"{SSHA512.base64}" + b64(sshaRaw),
		"{SSHA512.B64}" + b64(sshaRaw),
		"{ssha512.BASE64}" + b64(sshaRaw),
		"{sha512}" + b64(sha[:]),
		"{SHA512.hex}" + hex.EncodeToString(sha[:]),
		"{SHA512.base64}" + b64(sha[:]),
		"{SHA512}" + hex.EncodeToString(sha[:]),
		"{blf-crypt}" + bc2y,
		"{Blf-Crypt}" + string(bc),
		"{CRYPT}" + bc2y,
		"{crypt}" + string(bc),
	}
}

// TestVerifyPasswordAcceptsDovecotSpellings: every Dovecot spelling of a scheme sora
// verifies checks the right password and refuses a wrong one as a wrong password.
func TestVerifyPasswordAcceptsDovecotSpellings(t *testing.T) {
	const password = "correct horse"
	for _, stored := range dovecotSpellings(t, password) {
		t.Run(stored[:strings.IndexByte(stored, '}')+1], func(t *testing.T) {
			if err := VerifyPassword(stored, password); err != nil {
				t.Errorf("VerifyPassword(%q, right password) = %v, want nil", stored, err)
			}
			if err := VerifyPassword(stored, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("VerifyPassword(%q, wrong password) = %v, want ErrInvalidCredentials", stored, err)
			}
		})
	}
}

// lockedBuffer collects log output; the slog handler may write from any goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestVerifyPasswordDoesNotLogTheStoredValue: no part of a stored password value
// reaches the log, at any level. A value VerifyPassword cannot check may be the
// password itself, pasted into the hash field; it used to be logged at ERROR on every
// login ("hash_prefix", the first 10 characters), and every SSHA512 verification
// logged the first 30 characters of the hash at DEBUG.
func TestVerifyPasswordDoesNotLogTheStoredValue(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })

	const password = "Secret-2026"
	ssha, err := GenerateSSHA512Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range []string{
		password, // a password in the hash field
		sha512CryptOfSecret,
		"{SSHA512}" + base64.StdEncoding.EncodeToString([]byte(password)), // too short to hold a salt
		"{SSHA512.hex}not-hex-" + password,
		ssha,
	} {
		_ = VerifyPassword(stored, password)
		_ = VerifyPassword(stored, "wrong")

		// What follows the {SCHEME} prefix (all of it when there is none).
		value := stored[strings.IndexByte(stored, '}')+1:]
		if piece := value[:min(8, len(value))]; strings.Contains(logs.String(), piece) {
			t.Errorf("verifying against %q logged %q from it:\n%s", stored, piece, logs.String())
		}
	}
}

// TestValidatePasswordHash: ValidatePasswordHash accepts exactly the values
// VerifyPassword can check, and refuses the others with ErrUnverifiableHash and a
// reason that quotes no part of the value.
func TestValidatePasswordHash(t *testing.T) {
	bc, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ssha, _ := GenerateSSHA512Hash("pw")
	sshaHex, _ := GenerateSSHA512HashHex("pw")
	blf, _ := GenerateBcryptHash("pw")
	accepted := append(dovecotSpellings(t, "pw"),
		ssha, sshaHex, blf, GenerateSHA512Hash("pw"), GenerateSHA512HashHex("pw"),
		string(bc), "$2b$"+string(bc[4:]), "$2y$"+string(bc[4:]),
	)
	for _, hash := range accepted {
		if err := ValidatePasswordHash(hash); err != nil {
			t.Errorf("ValidatePasswordHash(%q) = %v, want nil", hash, err)
		}
	}

	salt := strings.Repeat("s", 22)
	for _, hash := range []string{
		"",
		"Secret-2026",
		"{Secret}2026",
		"{PLAIN}Secret-2026",
		sha512CryptOfSecret,
		"{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"{CRYPT}" + sha512CryptOfSecret[len("{SHA512-CRYPT}"):], // crypt(3) SHA-512
		"{CRYPT}abJnggxhB/yWI",             // crypt(3) DES
		"$1$saltsalt$hashhashhashhashhash", // MD5-CRYPT without a scheme
		"{SSHA512" + ssha[len("{SSHA512}"):],
		"{SSHA512.}" + ssha[len("{SSHA512}"):],
		"{SSHA512.b32}" + ssha[len("{SSHA512}"):],
		"{SSHA512}" + base64.StdEncoding.EncodeToString([]byte("tooshort")),
		"{SSHA512}not base64!",
		"{SSHA512.hex}" + sshaHex[len("{SSHA512.HEX}"):] + "z",
		"{SHA512}" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 96)), // not hex either
		"{SHA512.hex}" + hex.EncodeToString(make([]byte, 63)),
		"{BLF-CRYPT}$2a$12$tooShortToBeBcrypt",
		blf + "\n",
		"$2a$03$" + salt + strings.Repeat("h", 31), // cost below bcrypt.MinCost
		"$2a$1x$" + salt + strings.Repeat("h", 31),
		"$2a$12$" + salt + strings.Repeat("h", 30) + "+", // not bcrypt's base64
		"$2x$" + string(bc[4:]),                          // crypt_blowfish's bug-compatible variant
		"{BLF-CRYPT}$2x$" + string(bc[4:]),
	} {
		err := ValidatePasswordHash(hash)
		if !errors.Is(err, ErrUnverifiableHash) {
			t.Errorf("ValidatePasswordHash(%q) = %v, want ErrUnverifiableHash", hash, err)
			continue
		}
		if verr := VerifyPassword(hash, "pw"); !errors.Is(verr, ErrUnverifiableHash) || errors.Is(verr, ErrInvalidCredentials) {
			t.Errorf("VerifyPassword(%q) = %v, want ErrUnverifiableHash and not ErrInvalidCredentials", hash, verr)
		}
		value := hash[strings.IndexByte(hash, '}')+1:]
		if piece := value[:min(6, len(value))]; len(piece) >= 4 && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(piece)) {
			t.Errorf("ValidatePasswordHash(%q) = %q: quotes %q from the value", hash, err, piece)
		}
		if strings.Contains(strings.ToLower(err.Error()), "secret") {
			t.Errorf("ValidatePasswordHash(%q) = %q: quotes the value", hash, err)
		}
	}
}
