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
	ssha512PrefixB64         = "{SSHA512}"
	ssha512PrefixB64Explicit = "{SSHA512.b64}"
	ssha512PrefixHex         = "{SSHA512.HEX}"

	sha512PrefixB64         = "{SHA512}"
	sha512PrefixB64Explicit = "{SHA512.b64}"
	sha512PrefixHex         = "{SHA512.HEX}"

	blfCryptPrefix = "{BLF-CRYPT}"

	// Standard bcrypt prefixes
	bcryptPrefix2a = "$2a$"
	bcryptPrefix2b = "$2b$"
	bcryptPrefix2y = "$2y$"

	// sha512HashLength is the expected length of a SHA512 hash in bytes.
	sha512HashLength = 64
	// ssha512MinSaltLength is the minimum length of a salt for SSHA512.
	ssha512MinSaltLength = 1 // A salt must exist
)

// verifySSHA512 checks if the provided password matches the SSHA512 hashed password
func verifySSHA512(hashedPassword, password string) error {
	hashPrefix := hashedPassword
	if len(hashPrefix) > 30 {
		hashPrefix = hashPrefix[:30] + "..."
	}
	logger.Debug("verifySSHA512: Starting verification", "hash_prefix", hashPrefix)

	decoded, err := decodePasswordData(hashedPassword, ssha512PrefixB64, ssha512PrefixB64Explicit, ssha512PrefixHex)
	if err != nil {
		logger.Debug("verifySSHA512: Decode failed", "hash_prefix", hashPrefix, "error", err)
		return fmt.Errorf("invalid SSHA512 format/data: %w", err)
	}

	// The SHA512 hash is 64 bytes (512 bits / 8 bits per byte)
	// Everything after that is the salt
	if len(decoded) < sha512HashLength+ssha512MinSaltLength {
		logger.Debug("verifySSHA512: Hash too short", "decoded_len", len(decoded), "hash_prefix", hashPrefix)
		return errors.New("invalid SSHA512 hash: too short")
	}

	// Extract the hash and salt
	storedHash := decoded[:sha512HashLength]
	salt := decoded[sha512HashLength:]

	logger.Debug("verifySSHA512: Extracted components", "salt_len", len(salt), "hash_prefix", hashPrefix)

	// Calculate hash for the provided password with the same salt
	h := sha512.New()
	h.Write([]byte(password))
	h.Write(salt)
	calculatedHash := h.Sum(nil)

	// Compare the hashes using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(storedHash, calculatedHash) != 1 {
		logger.Debug("verifySSHA512: Hash mismatch", "salt_len", len(salt), "hash_prefix", hashPrefix)
		return errors.New("invalid password")
	}

	logger.Debug("verifySSHA512: Verification SUCCESS", "salt_len", len(salt), "hash_prefix", hashPrefix)
	return nil
}

// verifySHA512 checks if the provided password matches the SHA512 hashed password (without salt)
// The format is {SHA512}base64_encoded_data, {SHA512.b64}base64_encoded_data or {SHA512.HEX}hex_encoded_data
func verifySHA512(hashedPassword, password string) error {
	storedHash, err := decodePasswordData(hashedPassword, sha512PrefixB64, sha512PrefixB64Explicit, sha512PrefixHex)
	if err != nil {
		return fmt.Errorf("invalid SHA512 format/data: %w", err)
	}

	// SHA512 hash should be exactly 64 bytes
	if len(storedHash) != sha512HashLength {
		return errors.New("invalid SHA512 hash: incorrect length")
	}

	// Calculate hash for the provided password
	h := sha512.New()
	h.Write([]byte(password))
	calculatedHash := h.Sum(nil)

	// Compare the hashes using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(storedHash, calculatedHash) != 1 {
		return errors.New("invalid password")
	}

	return nil
}

// verifyBcrypt checks if the provided password matches the bcrypt hashed password
func verifyBcrypt(hashedPassword, password string) error {
	// For {BLF-CRYPT}, remove the prefix unconditionally
	hashedPassword = strings.TrimPrefix(hashedPassword, blfCryptPrefix)

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
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

// SetBcryptCost sets the bcrypt cost (clamped to [10,14]) and regenerates the timing
// dummy hash so DummyVerifyPassword keeps matching real-verify timing. Call once at
// startup, before serving.
func SetBcryptCost(cost int) {
	if cost < 10 {
		cost = 10
	}
	if cost > 14 {
		cost = 14
	}
	BcryptCost = cost
	if h, err := bcrypt.GenerateFromPassword([]byte("sora-timing-equalization-placeholder"), BcryptCost); err == nil {
		dummyBcryptHash = h
	}
}

// GenerateBcryptHash creates a new bcrypt hash with the BLF-CRYPT prefix
// Returns a string in the format {BLF-CRYPT}bcrypt_hash
func GenerateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("error generating bcrypt hash: %w", err)
	}

	return blfCryptPrefix + string(hash), nil
}

// verifyPassword checks if the provided password matches the stored password hash
// It supports bcrypt, BLF-CRYPT, SSHA512, and SHA512 formats with different encodings
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

	switch {
	case strings.HasPrefix(hashedPassword, ssha512PrefixB64),
		strings.HasPrefix(hashedPassword, ssha512PrefixB64Explicit),
		strings.HasPrefix(hashedPassword, ssha512PrefixHex):
		hashType = "ssha512"
		err = verifySSHA512(hashedPassword, password)
		return err

	case strings.HasPrefix(hashedPassword, sha512PrefixB64),
		strings.HasPrefix(hashedPassword, sha512PrefixB64Explicit),
		strings.HasPrefix(hashedPassword, sha512PrefixHex):
		hashType = "sha512"
		err = verifySHA512(hashedPassword, password)
		return err

	case strings.HasPrefix(hashedPassword, blfCryptPrefix):
		// BLF-CRYPT is just bcrypt with a prefix
		hashType = "blf_crypt"
		err = verifyBcrypt(hashedPassword, password)
		return err

	// Without scheme, we default to Bcrypt
	case strings.HasPrefix(hashedPassword, bcryptPrefix2a),
		strings.HasPrefix(hashedPassword, bcryptPrefix2b),
		strings.HasPrefix(hashedPassword, bcryptPrefix2y):
		// Standard bcrypt format
		hashType = "bcrypt"
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		return err

	default:
		// No known scheme prefix
		hashType = "unknown"
		logger.Error("Database: unknown password hash scheme", "hash_prefix", hashedPassword[:min(10, len(hashedPassword))])
		err = errors.New("unknown password hash scheme")
		return err
	}
}

// dummyBcryptHash is a fixed, valid bcrypt hash at the current default cost. It is never
// a real credential — it exists only to burn the same CPU as a genuine password
// verification on auth paths that would otherwise short-circuit (account not found).
var dummyBcryptHash []byte

func init() {
	// Generated once at startup so the cost always tracks BcryptCost (rather than
	// drifting if the bcrypt default changes). The one-time cost is negligible.
	if h, err := bcrypt.GenerateFromPassword([]byte("sora-timing-equalization-placeholder"), BcryptCost); err == nil {
		dummyBcryptHash = h
	} else {
		// Defensive: GenerateFromPassword effectively never fails. Fall back to a known
		// valid cost-10 hash so DummyVerifyPassword still performs real bcrypt work
		// (a malformed hash would return instantly and defeat timing equalization).
		dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	}
}

// DummyVerifyPassword performs a constant-cost bcrypt comparison that always fails.
// Call it on the "account not found" branch of an authentication path so the response
// takes ~the same time as the "wrong password" branch (which runs bcrypt). Without it,
// a non-existent account returns measurably faster than an existing one, giving an
// attacker a user-enumeration timing oracle. (security-audit M14)
func DummyVerifyPassword(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
}

// needsRehash checks if a bcrypt hash needs to be rehashed with the current default cost
func NeedsRehash(hash string) bool {
	// Only check bcrypt hashes
	hash = strings.TrimPrefix(hash, "{BLF-CRYPT}")

	// Check if it's a bcrypt hash
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
		return false
	}

	// Extract the cost
	// bcrypt hash format: $2a$cost$...
	parts := strings.Split(hash, "$")
	if len(parts) < 3 {
		return false
	}

	costStr := strings.TrimRight(parts[2], "0123456789")
	if costStr != "" {
		// Invalid format
		return false
	}

	// Current cost should be between the $2a$ and the next $
	currentCost := parts[2]
	defaultCost := fmt.Sprintf("%02d", BcryptCost)

	return currentCost != defaultCost
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

// decodePasswordData handles prefix checking and decoding for common hash formats.
// It returns the raw decoded data.
func decodePasswordData(hashedPassword, pB64, pB64Explicit, pHex string) (data []byte, err error) {
	var encodedData string
	var isHexEncoded bool

	switch {
	case strings.HasPrefix(hashedPassword, pB64Explicit): // Check more specific explicit b64 first
		encodedData = hashedPassword[len(pB64Explicit):]
	case strings.HasPrefix(hashedPassword, pB64):
		encodedData = hashedPassword[len(pB64):]
	case strings.HasPrefix(hashedPassword, pHex):
		encodedData = hashedPassword[len(pHex):]
		isHexEncoded = true
	default:
		return nil, fmt.Errorf("invalid or missing prefix (expected one of %s, %s, %s)", pB64, pB64Explicit, pHex)
	}

	if isHexEncoded {
		data, err = hex.DecodeString(encodedData)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex data: %w", err)
		}
	} else {
		data, err = base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64 data: %w", err)
		}
	}
	return data, nil
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
