package db

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestVerifyPassword(t *testing.T) {
	// Test standard bcrypt
	password := "testPassword123"
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	err = VerifyPassword(string(bcryptHash), password)
	if err != nil {
		t.Errorf("bcrypt verification failed for correct password: %v", err)
	}

	err = VerifyPassword(string(bcryptHash), "wrongPassword")
	if err == nil {
		t.Error("bcrypt verification should fail for incorrect password")
	}

	// Test BLF-CRYPT
	blfCryptHash, err := GenerateBcryptHash(password)
	if err != nil {
		t.Fatalf("Failed to generate BLF-CRYPT hash: %v", err)
	}

	if !strings.HasPrefix(blfCryptHash, "{BLF-CRYPT}") {
		t.Errorf("BLF-CRYPT hash doesn't have the correct prefix: %s", blfCryptHash)
	}

	err = VerifyPassword(blfCryptHash, password)
	if err != nil {
		t.Errorf("BLF-CRYPT verification failed for correct password: %v", err)
	}

	err = VerifyPassword(blfCryptHash, "wrongPassword")
	if err == nil {
		t.Error("BLF-CRYPT verification should fail for incorrect password")
	}

	// Test SSHA512 with base64 encoding
	ssha512Hash, err := GenerateSSHA512Hash(password)
	if err != nil {
		t.Fatalf("Failed to generate SSHA512 hash: %v", err)
	}

	if !strings.HasPrefix(ssha512Hash, "{SSHA512}") {
		t.Errorf("SSHA512 hash doesn't have the correct prefix: %s", ssha512Hash)
	}

	err = VerifyPassword(ssha512Hash, password)
	if err != nil {
		t.Errorf("SSHA512 verification failed for correct password: %v", err)
	}

	err = VerifyPassword(ssha512Hash, "wrongPassword")
	if err == nil {
		t.Error("SSHA512 verification should fail for incorrect password")
	}

	// Test SSHA512 with hex encoding
	ssha512HexHash, err := GenerateSSHA512HashHex(password)
	if err != nil {
		t.Fatalf("Failed to generate SSHA512.HEX hash: %v", err)
	}

	if !strings.HasPrefix(ssha512HexHash, "{SSHA512.HEX}") {
		t.Errorf("SSHA512.HEX hash doesn't have the correct prefix: %s", ssha512HexHash)
	}

	err = VerifyPassword(ssha512HexHash, password)
	if err != nil {
		t.Errorf("SSHA512.HEX verification failed for correct password: %v", err)
	}

	err = VerifyPassword(ssha512HexHash, "wrongPassword")
	if err == nil {
		t.Error("SSHA512.HEX verification should fail for incorrect password")
	}

	// Test SHA512 with base64 encoding
	sha512Hash := GenerateSHA512Hash(password)
	if !strings.HasPrefix(sha512Hash, "{SHA512}") {
		t.Errorf("SHA512 hash doesn't have the correct prefix: %s", sha512Hash)
	}

	err = VerifyPassword(sha512Hash, password)
	if err != nil {
		t.Errorf("SHA512 verification failed for correct password: %v", err)
	}

	err = VerifyPassword(sha512Hash, "wrongPassword")
	if err == nil {
		t.Error("SHA512 verification should fail for incorrect password")
	}

	// Test SHA512 with hex encoding
	sha512HexHash := GenerateSHA512HashHex(password)
	if !strings.HasPrefix(sha512HexHash, "{SHA512.HEX}") {
		t.Errorf("SHA512.HEX hash doesn't have the correct prefix: %s", sha512HexHash)
	}

	err = VerifyPassword(sha512HexHash, password)
	if err != nil {
		t.Errorf("SHA512.HEX verification failed for correct password: %v", err)
	}

	err = VerifyPassword(sha512HexHash, "wrongPassword")
	if err == nil {
		t.Error("SHA512.HEX verification should fail for incorrect password")
	}

	// Test with malformed hash
	err = VerifyPassword("unknown_scheme_hash", password)
	if err == nil {
		t.Error("Verification should fail for unknown hash scheme")
	}
}

func TestVerifySSHA512(t *testing.T) {
	password := "testPassword123"

	// Test with both base64 and hex encodings
	tests := []struct {
		name      string
		createFn  func(string) (string, error)
		hasPrefix string
	}{
		{
			name:      "SSHA512 Base64",
			createFn:  GenerateSSHA512Hash,
			hasPrefix: "{SSHA512}",
		},
		{
			name:      "SSHA512 Hex",
			createFn:  GenerateSSHA512HashHex,
			hasPrefix: "{SSHA512.HEX}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate hash
			hash, err := tt.createFn(password)
			if err != nil {
				t.Fatalf("Failed to generate hash: %v", err)
			}

			// Verify prefix
			if !strings.HasPrefix(hash, tt.hasPrefix) {
				t.Errorf("Hash doesn't have the correct prefix. Expected prefix: %s, got hash: %s", tt.hasPrefix, hash)
			}

			// Test correct password
			err = VerifyPassword(hash, password)
			if err != nil {
				t.Errorf("Verification failed for correct password: %v", err)
			}

			// Test wrong password
			err = VerifyPassword(hash, "wrongPassword")
			if err == nil {
				t.Error("Verification should fail for incorrect password")
			}

			// Test two different hashes for the same password should be different (random salt)
			hash2, err := tt.createFn(password)
			if err != nil {
				t.Fatalf("Failed to generate second hash: %v", err)
			}

			if hash == hash2 {
				t.Error("Two generated hashes should be different due to random salt")
			}

			// But both should verify correctly
			err = VerifyPassword(hash2, password)
			if err != nil {
				t.Errorf("Second hash verification failed for correct password: %v", err)
			}
		})
	}

	// Test malformed SSHA512 hash
	err := VerifyPassword("{SSHA512}invalidBase64", password)
	if err == nil {
		t.Error("Verification should fail for malformed hash")
	}

	// Test with invalid format prefix
	err = VerifyPassword("{INVALID}hash", password)
	if err == nil {
		t.Error("Verification should fail for invalid format prefix")
	}

	// Test with too short hash
	shortHash := "{SSHA512}" + base64.StdEncoding.EncodeToString([]byte("tooshort"))
	err = VerifyPassword(shortHash, password)
	if err == nil {
		t.Error("Verification should fail for too short hash")
	}
}

func TestVerifySHA512(t *testing.T) {
	password := "testPassword123"

	// Test with both base64 and hex encodings
	tests := []struct {
		name      string
		createFn  func(string) string
		hasPrefix string
	}{
		{
			name:      "SHA512 Base64",
			createFn:  GenerateSHA512Hash,
			hasPrefix: "{SHA512}",
		},
		{
			name:      "SHA512 Hex",
			createFn:  GenerateSHA512HashHex,
			hasPrefix: "{SHA512.HEX}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate hash
			hash := tt.createFn(password)

			// Verify prefix
			if !strings.HasPrefix(hash, tt.hasPrefix) {
				t.Errorf("Hash doesn't have the correct prefix. Expected prefix: %s, got hash: %s", tt.hasPrefix, hash)
			}

			// Test correct password
			err := VerifyPassword(hash, password)
			if err != nil {
				t.Errorf("Verification failed for correct password: %v", err)
			}

			// Test wrong password
			err = VerifyPassword(hash, "wrongPassword")
			if err == nil {
				t.Error("Verification should fail for incorrect password")
			}

			// Same password should always generate the same hash (no salt)
			hash2 := tt.createFn(password)
			if hash != hash2 {
				t.Error("Two generated hashes for the same password should be identical (no salt)")
			}
		})
	}

	// Test malformed SHA512 hash
	err := VerifyPassword("{SHA512}invalidBase64", password)
	if err == nil {
		t.Error("Verification should fail for malformed hash")
	}

	// Test with invalid format prefix
	err = VerifyPassword("{INVALID}hash", password)
	if err == nil {
		t.Error("Verification should fail for invalid format prefix")
	}
}

func TestManuallyCreatedHashes(t *testing.T) {
	// Test a manually created SHA512 hash for verification
	password := "test123"

	// Create a SHA512 hash manually
	h := sha512.New()
	h.Write([]byte(password))
	hash := h.Sum(nil)

	// Encode with base64
	b64Hash := "{SHA512}" + base64.StdEncoding.EncodeToString(hash)
	err := VerifyPassword(b64Hash, password)
	if err != nil {
		t.Errorf("Manually created SHA512 base64 hash verification failed: %v", err)
	}

	// Encode with hex
	hexHash := "{SHA512.HEX}" + hex.EncodeToString(hash)
	err = VerifyPassword(hexHash, password)
	if err != nil {
		t.Errorf("Manually created SHA512 hex hash verification failed: %v", err)
	}

	// Create a SSHA512 hash manually with a known salt
	salt := []byte("saltsalt") // 8-byte salt
	h = sha512.New()
	h.Write([]byte(password))
	h.Write(salt)
	sshaHash := h.Sum(nil)

	// Combine hash and salt, then encode with base64
	combined := append(sshaHash, salt...)
	b64SSHA := "{SSHA512}" + base64.StdEncoding.EncodeToString(combined)
	err = VerifyPassword(b64SSHA, password)
	if err != nil {
		t.Errorf("Manually created SSHA512 base64 hash verification failed: %v", err)
	}

	// Combine hash and salt, then encode with hex
	hexSSHA := "{SSHA512.HEX}" + hex.EncodeToString(combined)
	err = VerifyPassword(hexSSHA, password)
	if err != nil {
		t.Errorf("Manually created SSHA512 hex hash verification failed: %v", err)
	}
}

// Note: TestNeedsRehash is already implemented in auth_rehash_test.go

// TestPasswordGenerationAndVerification tests all hash types end-to-end
func TestPasswordGenerationAndVerification(t *testing.T) {
	password := "testPassword123!"

	tests := []struct {
		name     string
		hashType string
		genFunc  func(string) (string, error)
	}{
		{
			name:     "bcrypt",
			hashType: "bcrypt",
			genFunc:  func(p string) (string, error) { return GenerateBcryptHash(p) },
		},
		{
			name:     "ssha512",
			hashType: "ssha512",
			genFunc:  func(p string) (string, error) { return GenerateSSHA512Hash(p) },
		},
		{
			name:     "ssha512 hex",
			hashType: "ssha512_hex",
			genFunc:  func(p string) (string, error) { return GenerateSSHA512HashHex(p) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate hash
			hash, err := tt.genFunc(password)
			require.NoError(t, err)
			require.NotEmpty(t, hash)

			// Verify correct password
			err = VerifyPassword(hash, password)
			assert.NoError(t, err)

			// Verify incorrect password
			err = VerifyPassword(hash, "wrongPassword")
			assert.Error(t, err)

			// Test with empty password
			err = VerifyPassword(hash, "")
			assert.Error(t, err)
		})
	}
}

// TestPasswordEdgeCases tests edge cases and error conditions
func TestPasswordEdgeCases(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		hash, err := GenerateBcryptHash("")
		require.NoError(t, err)

		err = VerifyPassword(hash, "")
		assert.NoError(t, err)
	})

	t.Run("very long password", func(t *testing.T) {
		longPassword := strings.Repeat("a", 1000)
		_, err := GenerateBcryptHash(longPassword)
		// bcrypt has a 72-byte limit, so this should fail, as a request error
		// (the caller's 400), not as a failure of the server
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password length exceeds 72 bytes")
		assert.ErrorIs(t, err, ErrInvalidAccountRequest)
	})

	t.Run("unicode password", func(t *testing.T) {
		unicodePassword := "测试密码🔒"
		hash, err := GenerateBcryptHash(unicodePassword)
		require.NoError(t, err)

		err = VerifyPassword(hash, unicodePassword)
		assert.NoError(t, err)
	})

	t.Run("malformed hashes", func(t *testing.T) {
		malformedHashes := []string{
			"{INVALID}hash",
			"{SHA512}invalidbase64!@#",
			"{SSHA512}tooshort",
			"$2a$invalidcost$hash",
			"",
		}

		for _, hash := range malformedHashes {
			err := VerifyPassword(hash, "password")
			assert.Error(t, err, "Hash: %s", hash)
		}
	})
}

// TestVerifyPasswordMismatchIsErrInvalidCredentials pins that a wrong password is
// reported as ErrInvalidCredentials whatever scheme the stored hash uses, and that
// a hash which cannot be checked at all is not. The proxies decide on this whether
// a failed login is definitive (cached, logged as invalid_password) or a fault: an
// SSHA512/SHA512 mismatch used to be a bare "invalid password" error that they took
// for a transient database error (#342).
func TestVerifyPasswordMismatchIsErrInvalidCredentials(t *testing.T) {
	const password = "testPassword123"

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	ssha512B64, err := GenerateSSHA512Hash(password)
	require.NoError(t, err)
	ssha512Hex, err := GenerateSSHA512HashHex(password)
	require.NoError(t, err)

	schemes := []struct {
		name string
		hash string
	}{
		{"bcrypt", string(bcryptHash)},
		{"BLF-CRYPT", blfCryptPrefix + string(bcryptHash)},
		{"SSHA512", ssha512B64},
		{"SSHA512.HEX", ssha512Hex},
		{"SHA512", GenerateSHA512Hash(password)},
		{"SHA512.HEX", GenerateSHA512HashHex(password)},
	}
	for _, s := range schemes {
		t.Run(s.name, func(t *testing.T) {
			require.NoError(t, VerifyPassword(s.hash, password))

			err := VerifyPassword(s.hash, "wrongPassword")
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("VerifyPassword with a wrong password = %v, want an error matching ErrInvalidCredentials", err)
			}
		})
	}

	t.Run("bcrypt keeps its own sentinel", func(t *testing.T) {
		err := VerifyPassword(string(bcryptHash), "wrongPassword")
		assert.ErrorIs(t, err, bcrypt.ErrMismatchedHashAndPassword)
	})

	t.Run("unverifiable hash is not a mismatch", func(t *testing.T) {
		for _, hash := range []string{
			"{INVALID}hash",
			"{SHA512}invalidbase64!@#",
			"{SSHA512}tooshort",
			"$2a$invalidcost$hash",
			"",
		} {
			err := VerifyPassword(hash, password)
			if err == nil || errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("VerifyPassword(%q) = %v, want a non-nil error that is not ErrInvalidCredentials", hash, err)
			}
		}
	})
}

// Database test helpers moved to test_helpers_test.go

// TestUpdatePassword tests password updating functionality
func TestUpdatePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	testDB := setupTestDatabase(t)
	defer testDB.Close()

	ctx := context.Background()

	// First create a test account
	tx, err := testDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create test account with unique email
	testEmail := fmt.Sprintf("testuser_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "originalpassword",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = testDB.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test password update
	tx2, err := testDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	// Generate new password hash
	newHash, err := GenerateBcryptHash("newpassword123")
	require.NoError(t, err)

	// Update password
	err = testDB.UpdatePassword(ctx, tx2, testEmail, newHash)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify the password was updated by trying to authenticate
	_, storedHash, err := testDB.GetCredentialForAuth(ctx, testEmail)
	require.NoError(t, err)

	// Old password should fail
	err = VerifyPassword(storedHash, "originalpassword")
	assert.Error(t, err)

	// New password should work
	err = VerifyPassword(storedHash, "newpassword123")
	assert.NoError(t, err)
}

// TestGetCredentialForAuth tests credential retrieval for authentication
func TestGetCredentialForAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	testDB := setupTestDatabase(t)
	defer testDB.Close()

	ctx := context.Background()

	// Create a test account first
	tx, err := testDB.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	testEmail := fmt.Sprintf("testauth_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "testpassword123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = testDB.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 1: Valid user
	accountID, hashedPassword, err := testDB.GetCredentialForAuth(ctx, testEmail)
	assert.NoError(t, err)
	assert.Greater(t, accountID, int64(0))
	assert.NotEmpty(t, hashedPassword)

	// Verify the returned hash works
	err = VerifyPassword(hashedPassword, "testpassword123")
	assert.NoError(t, err)

	// Test 2: Non-existent user
	_, _, err = testDB.GetCredentialForAuth(ctx, "nonexistent@example.com")
	assert.Error(t, err)

	// Test 3: Empty address
	_, _, err = testDB.GetCredentialForAuth(ctx, "")
	assert.Error(t, err)

	// Test 4: Case insensitive lookup
	upperCaseEmail := strings.ToUpper(testEmail)
	accountID2, hashedPassword2, err := testDB.GetCredentialForAuth(ctx, upperCaseEmail)
	assert.NoError(t, err)
	assert.Equal(t, accountID, accountID2)
	assert.Equal(t, hashedPassword, hashedPassword2)
}

// TestGetAccountIDByAddress tests account ID lookup by address
func TestGetAccountIDByAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create a test account
	testEmail := fmt.Sprintf("test_get_account_%d@example.com", time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Test cases:
	// 1. Valid user
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	assert.NoError(t, err)
	assert.Greater(t, accountID, int64(0))

	// 2. Non-existent user (should return ErrUserNotFound)
	_, err = db.GetAccountIDByAddress(ctx, "nonexistent@example.com")
	assert.Error(t, err)
	// 3. Empty address (should return error)
	// 4. Case insensitive lookup
	// 5. Normalized address handling
}

// GetAccountAddresses answers, for any address of an account, that account's ID and all
// of its addresses, and ErrUserNotFound for an address no account has.
func TestGetAccountAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	primary := fmt.Sprintf("get-addresses-%d@example.com", suffix)
	alias := fmt.Sprintf("get-addresses-alias-%d@example.org", suffix)
	accountID := createAccountWithCredential(t, database, ctx, primary)
	addCredential(t, database, ctx, accountID, alias)
	createAccountWithCredential(t, database, ctx, fmt.Sprintf("get-addresses-other-%d@example.com", suffix))

	for _, address := range []string{primary, alias, " " + strings.ToUpper(alias) + " "} {
		id, addresses, err := database.GetAccountAddresses(ctx, address)
		require.NoError(t, err, address)
		assert.Equal(t, accountID, id, address)
		assert.ElementsMatch(t, []string{primary, alias}, addresses, address)
	}

	_, _, err := database.GetAccountAddresses(ctx, fmt.Sprintf("get-addresses-unknown-%d@example.com", suffix))
	assert.ErrorIs(t, err, consts.ErrUserNotFound)
	_, _, err = database.GetAccountAddresses(ctx, " ")
	assert.Error(t, err)
}

// TestGetPrimaryEmailForAccount tests primary email retrieval
func TestGetPrimaryEmailForAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create a test account
	testEmail := fmt.Sprintf("test_primary_email_%d@example.com", time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Test cases:
	// 1. Account with primary email
	primaryEmail, err := db.GetPrimaryEmailForAccount(ctx, accountID)
	assert.NoError(t, err)
	assert.Equal(t, testEmail, primaryEmail.FullAddress())

	// 2. Non-existent account (should return error)
	_, err = db.GetPrimaryEmailForAccount(ctx, 99999999)
	assert.Error(t, err)
	// 3. Account without primary email (should return error)
	// 4. Valid address format in response
}
