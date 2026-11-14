package db

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

const (
	ssha512PrefixB64 = "{SSHA512}"
	ssha512PrefixHex = "{SSHA512.HEX}"

	sha512PrefixB64 = "{SHA512}"
	sha512PrefixHex = "{SHA512.HEX}"

	blfCryptPrefix = "{BLF-CRYPT}"
)

// verifySSHA512 checks password against SSHA512 data: the SHA-512 digest of the
// password and the salt, followed by the salt (parsePasswordHash checked the length).
func verifySSHA512(data []byte, password string) error {
	digest, salt := data[:sha512.Size], data[sha512.Size:]

	h := sha512.New()
	h.Write([]byte(password))
	h.Write(salt)

	// Compare the hashes using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(digest, h.Sum(nil)) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// verifySHA512 checks password against SHA512 data: the unsalted SHA-512 digest.
func verifySHA512(data []byte, password string) error {
	digest := sha512.Sum512([]byte(password))

	// Compare the hashes using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(data, digest[:]) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// verifyBcrypt checks password against a bcrypt hash. A mismatch matches both
// ErrInvalidCredentials and bcrypt.ErrMismatchedHashAndPassword.
func verifyBcrypt(hash []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
	default:
		return fmt.Errorf("%w: %w", ErrUnverifiableHash, err)
	}
}

// GenerateSSHA512Hash creates a new SSHA512 password hash with a random salt
// Returns a string in the format {SSHA512}base64_encoded_data
func GenerateSSHA512Hash(password string) (string, error) {
	// Generate a random salt (8 bytes is common for salts)
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("error generating random salt: %w", err)
	}

	// Create hash with password and salt
	h := sha512.New()
	h.Write([]byte(password))
	h.Write(salt)
	hash := h.Sum(nil)

	// Combine hash and salt, then encode with base64
	combined := append(hash, salt...)
	encoded := base64.StdEncoding.EncodeToString(combined)

	return ssha512PrefixB64 + encoded, nil
}

// GenerateSSHA512HashHex creates a new SSHA512 password hash with a random salt
// Returns a string in the format {SSHA512.HEX}hex_encoded_data
func GenerateSSHA512HashHex(password string) (string, error) {
	// Generate a random salt (8 bytes is common for salts)
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("error generating random salt: %w", err)
	}

	// Create hash with password and salt
	h := sha512.New()
	h.Write([]byte(password))
	h.Write(salt)
	hash := h.Sum(nil)

	// Combine hash and salt, then encode with hex
	combined := append(hash, salt...)
	encoded := hex.EncodeToString(combined)

	return ssha512PrefixHex + encoded, nil
}

// GenerateSHA512Hash creates a new SHA512 password hash (without salt)
// Returns a string in the format {SHA512}base64_encoded_data
func GenerateSHA512Hash(password string) string {
	// Create hash with just the password
	h := sha512.New()
	h.Write([]byte(password))
	hash := h.Sum(nil)

	// Encode with base64
	encoded := base64.StdEncoding.EncodeToString(hash)

	return sha512PrefixB64 + encoded
}

// GenerateSHA512HashHex creates a new SHA512 password hash (without salt)
// Returns a string in the format {SHA512.HEX}hex_encoded_data
func GenerateSHA512HashHex(password string) string {
	// Create hash with just the password
	h := sha512.New()
	h.Write([]byte(password))
	hash := h.Sum(nil)

	// Encode with hex
	encoded := hex.EncodeToString(hash)

	return sha512PrefixHex + encoded
}

// BcryptCost is the cost used for password hashing and rehash decisions. Default 12;
// override at startup via SetBcryptCost (from config). Set once before serving, then
// read concurrently.
var BcryptCost = 12

// SetBcryptCost sets the bcrypt cost (clamped to [10,14]). Call once at
// startup, before serving. The timing dummy hash used by DummyVerifyPassword
// tracks the current cost automatically (see dummyHashForCurrentCost).
func SetBcryptCost(cost int) {
	if cost < 10 {
		cost = 10
	}
	if cost > 14 {
		cost = 14
	}
	BcryptCost = cost
}

// GenerateBcryptHash creates a new bcrypt hash with the BLF-CRYPT prefix
// Returns a string in the format {BLF-CRYPT}bcrypt_hash
// A password over bcrypt's 72-byte limit is the caller's request error and wraps
// ErrInvalidAccountRequest.
func GenerateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if errors.Is(err, bcrypt.ErrPasswordTooLong) {
		return "", fmt.Errorf("%w: %w", ErrInvalidAccountRequest, err)
	}
	if err != nil {
		return "", fmt.Errorf("error generating bcrypt hash: %w", err)
	}

	return blfCryptPrefix + string(hash), nil
}

// ErrUnsupportedHashType is returned for a hash type new passwords are not hashed with.
var ErrUnsupportedHashType = errors.New("unsupported hash type")

// ValidateNewHashType checks that hashType is one a new password is hashed with:
// bcrypt or ssha512. Unsalted SHA-512 is still verified for legacy credentials
// (VerifyPassword) but no longer written.
func ValidateNewHashType(hashType string) error {
	switch hashType {
	case "bcrypt", "ssha512":
		return nil
	}
	return fmt.Errorf("%w %q: use bcrypt or ssha512", ErrUnsupportedHashType, hashType)
}

// VerifyPassword checks if the provided password matches the stored password hash:
// SSHA512, SHA512, BLF-CRYPT or CRYPT (bcrypt) in any of Dovecot's spellings, or a
// bare bcrypt hash (see parsePasswordHash). A wrong password is reported as
// ErrInvalidCredentials (errors.Is) for every scheme; a stored hash that cannot be
// checked as ErrUnverifiableHash.
func VerifyPassword(hashedPassword, password string) error {
	start := time.Now()
	var hashType string
	var err error

	defer func() {
		status := "success"
		if err != nil {
			status = "failure"
		}
		// Use custom metric for password verification timing (not a DB query)
		metrics.PasswordVerificationAttempts.WithLabelValues(hashType, status).Inc()
		// Track duration to monitor bcrypt/hash performance
		duration := time.Since(start).Seconds()
		if duration > 0.1 { // Log slow password verifications (>100ms)
			logger.Info("Slow password verification", "type", hashType, "duration_ms", duration*1000, "status", status)
		}
	}()

	h, err := parsePasswordHash(hashedPassword)
	hashType = h.scheme
	if err != nil {
		if hashType == "" {
			hashType = "unknown"
		}
		// The error names the problem but no part of the value: it may be a password
		// pasted into the hash field.
		logger.Error("Password hash cannot be verified", "type", hashType, "error", err)
		return err
	}

	switch h.scheme {
	case "ssha512":
		err = verifySSHA512(h.data, password)
	case "sha512":
		err = verifySHA512(h.data, password)
	default: // bcrypt, blf_crypt, crypt
		err = verifyBcrypt(h.data, password)
	}
	return err
}

// dummyHash caches a valid bcrypt hash at dummyHashCost. It is never a real
// credential — it exists only to burn the same CPU as a genuine password
// verification on auth paths that would otherwise short-circuit (account not
// found). Generated lazily so it always tracks the current BcryptCost, no
// matter when or how the cost was set (SetBcryptCost at startup, or a test
// assigning BcryptCost directly in its own package init).
var (
	dummyHashMu   sync.Mutex
	dummyHashCost int // 0 = not yet generated
	dummyHash     []byte
)

// dummyHashForCurrentCost returns a valid bcrypt hash at the current
// BcryptCost, regenerating the cached one when the cost changes.
func dummyHashForCurrentCost() []byte {
	dummyHashMu.Lock()
	defer dummyHashMu.Unlock()
	if dummyHashCost != BcryptCost {
		if h, err := bcrypt.GenerateFromPassword([]byte("sora-timing-equalization-placeholder"), BcryptCost); err == nil {
			dummyHash = h
		} else {
			// Defensive: GenerateFromPassword effectively never fails. Fall back to a known
			// valid cost-10 hash so DummyVerifyPassword still performs real bcrypt work
			// (a malformed hash would return instantly and defeat timing equalization).
			dummyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
		}
		dummyHashCost = BcryptCost
	}
	return dummyHash
}

// DummyVerifyPassword performs a constant-cost bcrypt comparison that always fails.
// Call it on the "account not found" branch of an authentication path so the response
// takes ~the same time as the "wrong password" branch (which runs bcrypt). Without it,
// a non-existent account returns measurably faster than an existing one, giving an
// attacker a user-enumeration timing oracle. (security-audit M14)
func DummyVerifyPassword(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHashForCurrentCost(), []byte(password))
}

// NeedsRehash reports whether a bcrypt hash, in any spelling VerifyPassword accepts
// (bare, {BLF-CRYPT} or {CRYPT}), has a cost other than BcryptCost.
func NeedsRehash(hash string) bool {
	h, err := parsePasswordHash(hash)
	if err != nil || h.scheme == "ssha512" || h.scheme == "sha512" {
		return false
	}
	cost, err := bcrypt.Cost(h.data)
	return err == nil && cost != BcryptCost
}

// UpdatePassword updates the stored password for a user
func (db *Database) UpdatePassword(ctx context.Context, tx pgx.Tx, address string, newHashedPassword string) error {
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return errors.New("address cannot be empty")
	}

	_, err := tx.Exec(ctx,
		"UPDATE credentials SET password = $1 WHERE LOWER(address) = $2",
		newHashedPassword, normalizedAddress)
	if err != nil {
		logger.Error("Database: error updating password", "address", normalizedAddress, "err", err)
		return fmt.Errorf("database error updating password: %w", err)
	}

	return nil
}

// GetCredentialForAuth retrieves the account ID and hashed password for a given address.
// It does not perform any password verification.
func (db *Database) GetCredentialForAuth(ctx context.Context, address string) (accountID int64, hashedPassword string, err error) {
	start := time.Now()
	defer func() {
		status := "success"
		if err != nil {
			if errors.Is(err, consts.ErrUserNotFound) {
				status = "not_found"
			} else {
				status = "error"
			}
		}
		metrics.DBQueryDuration.WithLabelValues("auth_get_credential", "read").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("auth_get_credential", status, "read").Inc()
	}()

	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return 0, "", errors.New("address cannot be empty")
	}

	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT c.account_id, c.password
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, normalizedAddress).Scan(&accountID, &hashedPassword)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Address (identity) not found in the credentials table
			return 0, "", consts.ErrUserNotFound
		}
		// Log other unexpected database errors
		logger.Error("Database: error fetching credentials", "address", normalizedAddress, "err", err)
		return 0, "", fmt.Errorf("database error during authentication: %w", err)
	}

	return accountID, hashedPassword, nil
}

// GetCredentialEpoch returns the account ID and the credential's "password epoch"
// (its updated_at, which UpdateAccount bumps on every genuine password change) for
// an address, requiring the account to be active (not soft-deleted).
//
// The User API binds each issued JWT to this epoch so that a password change or
// account deletion invalidates previously issued tokens when they are refreshed —
// stateless JWTs are otherwise non-revocable. A transparent login rehash
// (UpdatePassword) deliberately does NOT bump updated_at, so it does not
// invalidate live sessions. Returns consts.ErrUserNotFound when the credential is
// missing or the account is soft-deleted.
func (db *Database) GetCredentialEpoch(ctx context.Context, address string) (accountID int64, epoch time.Time, err error) {
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return 0, time.Time{}, errors.New("address cannot be empty")
	}

	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT c.account_id, c.updated_at
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, normalizedAddress).Scan(&accountID, &epoch)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, time.Time{}, consts.ErrUserNotFound
		}
		logger.Error("Database: error fetching credential epoch", "address", normalizedAddress, "err", err)
		return 0, time.Time{}, fmt.Errorf("database error fetching credential epoch: %w", err)
	}

	return accountID, epoch, nil
}

// GetAccountIDByAddress retrieves the main user ID associated with a given identity (address)
// by looking it up in the `credentials` table.
func (db *Database) GetAccountIDByAddress(ctx context.Context, address string) (int64, error) {
	var accountID int64
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))

	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}

	// Query the credentials table for the account_id associated with the address
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, "SELECT account_id FROM credentials WHERE LOWER(address) = $1", normalizedAddress).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Identity (address) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		logger.Error("Database: error fetching account ID", "address", normalizedAddress, "err", err)
		return 0, fmt.Errorf("database error fetching account ID: %w", err)
	}
	return accountID, nil
}

// GetAccountAddresses returns the ID of the account that address is a credential of, as
// GetAccountIDByAddress does, and every address of that account (address included), in
// one query. It returns consts.ErrUserNotFound when no account has the address.
func (db *Database) GetAccountAddresses(ctx context.Context, address string) (int64, []string, error) {
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return 0, nil, errors.New("address cannot be empty")
	}

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT account_id, address FROM credentials
		WHERE account_id = (SELECT account_id FROM credentials WHERE LOWER(address) = $1)`, normalizedAddress)
	if err != nil {
		return 0, nil, fmt.Errorf("database error fetching account addresses: %w", err)
	}
	defer rows.Close()

	var accountID int64
	var addresses []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&accountID, &addr); err != nil {
			return 0, nil, fmt.Errorf("database error scanning account addresses: %w", err)
		}
		addresses = append(addresses, addr)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("database error fetching account addresses: %w", err)
	}
	if len(addresses) == 0 {
		return 0, nil, consts.ErrUserNotFound
	}
	return accountID, addresses, nil
}

// GetActiveAccountIDByAddress retrieves the account ID for a given credential address,
// ensuring the account is not deleted. This is the preferred method for LMTP/SMTP
// recipient validation where we need to reject deleted accounts.
func (db *Database) GetActiveAccountIDByAddress(ctx context.Context, address string) (int64, error) {
	var accountID int64
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))

	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}

	// Query credentials with account deletion check
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT c.account_id
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, normalizedAddress).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, consts.ErrUserNotFound
		}
		logger.Error("Database: error fetching active account ID", "address", normalizedAddress, "err", err)
		return 0, fmt.Errorf("database error fetching active account ID: %w", err)
	}
	return accountID, nil
}

// GetPrimaryEmailForAccount retrieves the primary email address for a given account ID.
func (db *Database) GetPrimaryEmailForAccount(ctx context.Context, accountID int64) (server.Address, error) {
	var email string
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx,
		"SELECT address FROM credentials WHERE account_id = $1 AND primary_identity = TRUE",
		accountID).Scan(&email)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// This case is an error because every account should have a primary email.
			return server.Address{}, fmt.Errorf("no primary email found for account ID %d", accountID)
		}
		return server.Address{}, fmt.Errorf("database error getting primary email for account ID %d: %w", accountID, err)
	}

	address, err := server.NewAddress(email)
	if err != nil {
		// This indicates a data integrity issue, as addresses in the DB should be valid.
		return server.Address{}, fmt.Errorf("invalid primary email format in database for account ID %d: %w", accountID, err)
	}

	return address, nil
}

var (
	// rehashSemaphore limits the number of concurrent bcrypt rehash operations
	// to prevent CPU exhaustion during large-scale legacy hash migrations.
	rehashSemaphore = make(chan struct{}, max(1, runtime.NumCPU()/2))
	rehashGroup     singleflight.Group
)

// QueueRehash securely schedules a password rehash operation.
// It uses singleflight to deduplicate concurrent rehash requests for the same address,
// and a semaphore to limit the total number of concurrent bcrypt operations globally.
func QueueRehash(key string, rehashFn func(ctx context.Context)) {
	go func() {
		// Recover so a panic in rehashFn (or re-panicked through singleflight to the
		// leader and every waiter on this key) drops the best-effort rehash instead of
		// crashing the whole process.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Rehash: panic recovered", "address", key, "panic", r, "stack", string(debug.Stack()))
			}
		}()
		rehashGroup.Do(key, func() (interface{}, error) {
			// Non-blocking acquire: when the rehash concurrency limit is saturated, shed
			// this rehash rather than parking the goroutine. Rehash is best-effort and
			// idempotent — the account keeps its legacy hash and is rehashed on a later
			// login — so spreading the work across logins beats queueing a goroutine per
			// login during a post-migration thundering herd.
			select {
			case rehashSemaphore <- struct{}{}:
				defer func() { <-rehashSemaphore }()
			default:
				logger.Debug("Rehash: skipped, concurrency limit reached", "address", key)
				return nil, nil
			}

			// Bound the rehash work (chiefly the DB update). bcrypt.GenerateFromPassword
			// is CPU-bound and does not observe ctx; the semaphore above is what caps
			// concurrent bcrypt cost.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			rehashFn(ctx)
			return nil, nil
		})
	}()
}
