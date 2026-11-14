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
