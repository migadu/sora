package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/migadu/sora/consts"
	"github.com/yugabyte/pgx/v5"
	"golang.org/x/crypto/bcrypt"
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
	decoded, err := decodePasswordData(hashedPassword, ssha512PrefixB64, ssha512PrefixB64Explicit, ssha512PrefixHex)
	if err != nil {
		return fmt.Errorf("invalid SSHA512 format/data: %w", err)
	}

	// The SHA512 hash is 64 bytes (512 bits / 8 bits per byte)
	// Everything after that is the salt
	if len(decoded) < sha512HashLength+ssha512MinSaltLength {
		return errors.New("invalid SSHA512 hash: too short")
	}

	// Extract the hash and salt
	storedHash := decoded[:sha512HashLength]
	salt := decoded[sha512HashLength:]

	// Calculate hash for the provided password with the same salt
	h := sha512.New()
	h.Write([]byte(password))
	h.Write(salt)
	calculatedHash := h.Sum(nil)

	// Compare the hashes
	if !bytes.Equal(storedHash, calculatedHash) {
		return errors.New("invalid password")
	}

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

	// Compare the hashes
	if !bytes.Equal(storedHash, calculatedHash) {
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

// GenerateBcryptHash creates a new bcrypt hash with the BLF-CRYPT prefix
// Returns a string in the format {BLF-CRYPT}bcrypt_hash
func GenerateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("error generating bcrypt hash: %w", err)
	}

	return blfCryptPrefix + string(hash), nil
}

// verifyPassword checks if the provided password matches the stored password hash
// It supports bcrypt, BLF-CRYPT, SSHA512, and SHA512 formats with different encodings
func verifyPassword(hashedPassword, password string) error {
	switch {
	case strings.HasPrefix(hashedPassword, ssha512PrefixB64),
		strings.HasPrefix(hashedPassword, ssha512PrefixB64Explicit),
		strings.HasPrefix(hashedPassword, ssha512PrefixHex):
		return verifySSHA512(hashedPassword, password)

	case strings.HasPrefix(hashedPassword, sha512PrefixB64),
		strings.HasPrefix(hashedPassword, sha512PrefixB64Explicit),
		strings.HasPrefix(hashedPassword, sha512PrefixHex):
		return verifySHA512(hashedPassword, password)

	case strings.HasPrefix(hashedPassword, blfCryptPrefix):
		// BLF-CRYPT is just bcrypt with a prefix
		return verifyBcrypt(hashedPassword, password)

	// Without scheme, we default to Bcrypt
	case strings.HasPrefix(hashedPassword, bcryptPrefix2a),
		strings.HasPrefix(hashedPassword, bcryptPrefix2b),
		strings.HasPrefix(hashedPassword, bcryptPrefix2y):
		// Standard bcrypt format
		return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	default:
		// No known scheme prefix
		log.Printf("Unknown password hash scheme: %s", hashedPassword[:min(10, len(hashedPassword))]) // Using built-in min
		return errors.New("unknown password hash scheme")
	}
}

// needsRehash checks if a bcrypt hash needs to be rehashed with the current default cost
func needsRehash(hash string) bool {
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
	defaultCost := fmt.Sprintf("%02d", bcrypt.DefaultCost)

	return currentCost != defaultCost
}

// UpdatePassword updates the stored password for a user
func (db *Database) UpdatePassword(ctx context.Context, address string, newHashedPassword string) error {
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return errors.New("address cannot be empty")
	}

	_, err := db.Pool.Exec(ctx,
		"UPDATE credentials SET password = $1 WHERE address = $2",
		newHashedPassword, normalizedAddress)

	if err != nil {
		log.Printf("error updating password for address %s: %v", normalizedAddress, err)
		return fmt.Errorf("database error updating password: %w", err)
	}

	return nil
}

// Authenticate verifies the provided address and password against the records
// in the `credentials` table. If successful, it returns the associated `account_id`.
// If the password's hash cost is different from the default, it will be re-hashed and updated.
func (db *Database) Authenticate(ctx context.Context, address string, password string) (int64, error) {
	var hashedPassword string
	var accountID int64

	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}
	if password == "" {
		return 0, errors.New("password cannot be empty")
	}

	err := db.Pool.QueryRow(ctx,
		"SELECT account_id, password FROM credentials WHERE address = $1",
		normalizedAddress).Scan(&accountID, &hashedPassword)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Address (identity) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		// Log other unexpected database errors
		log.Printf("error fetching credentials for address %s: %v", normalizedAddress, err)
		return 0, fmt.Errorf("database error during authentication: %w", err)
	}

	if err := verifyPassword(hashedPassword, password); err != nil {
		// Password does not match
		return 0, errors.New("invalid password")
	}

	// Authentication successful

	// Check if the password needs to be rehashed (bcrypt cost changed)
	if needsRehash(hashedPassword) {
		// Generate a new hash with the current default cost
		newHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("WARNING: failed to rehash password for address %s: %v", normalizedAddress, err)
			// Continue even if rehashing fails
		} else {
			// If it's a BLF-CRYPT format, preserve the prefix
			var newHashedPassword string
			if strings.HasPrefix(hashedPassword, "{BLF-CRYPT}") {
				newHashedPassword = "{BLF-CRYPT}" + string(newHash)
			} else {
				newHashedPassword = string(newHash)
			}

			// Update the stored password
			err = db.UpdatePassword(ctx, normalizedAddress, newHashedPassword)
			if err != nil {
				log.Printf("WARNING: failed to update rehashed password for address %s: %v", normalizedAddress, err)
				// Continue even if update fails
			} else {
				log.Printf("rehashed password with new cost for address %s", normalizedAddress)
			}
		}
	}

	return accountID, nil
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
	err := db.Pool.QueryRow(ctx, "SELECT account_id FROM credentials WHERE address = $1", normalizedAddress).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Identity (address) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		log.Printf("error fetching account ID for address %s: %v", normalizedAddress, err)
		return 0, fmt.Errorf("database error fetching account ID: %w", err)
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
