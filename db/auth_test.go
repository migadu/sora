package db

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestVerifyPassword(t *testing.T) {
	// Test standard bcrypt
	password := "testPassword123"
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	err = verifyPassword(string(bcryptHash), password)
	if err != nil {
		t.Errorf("bcrypt verification failed for correct password: %v", err)
	}

	err = verifyPassword(string(bcryptHash), "wrongPassword")
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

	err = verifyPassword(blfCryptHash, password)
	if err != nil {
		t.Errorf("BLF-CRYPT verification failed for correct password: %v", err)
	}

	err = verifyPassword(blfCryptHash, "wrongPassword")
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

	err = verifyPassword(ssha512Hash, password)
	if err != nil {
		t.Errorf("SSHA512 verification failed for correct password: %v", err)
	}

	err = verifyPassword(ssha512Hash, "wrongPassword")
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

	err = verifyPassword(ssha512HexHash, password)
	if err != nil {
		t.Errorf("SSHA512.HEX verification failed for correct password: %v", err)
	}

	err = verifyPassword(ssha512HexHash, "wrongPassword")
	if err == nil {
		t.Error("SSHA512.HEX verification should fail for incorrect password")
	}

	// Test SHA512 with base64 encoding
	sha512Hash := GenerateSHA512Hash(password)
	if !strings.HasPrefix(sha512Hash, "{SHA512}") {
		t.Errorf("SHA512 hash doesn't have the correct prefix: %s", sha512Hash)
	}

	err = verifyPassword(sha512Hash, password)
	if err != nil {
		t.Errorf("SHA512 verification failed for correct password: %v", err)
	}

	err = verifyPassword(sha512Hash, "wrongPassword")
	if err == nil {
		t.Error("SHA512 verification should fail for incorrect password")
	}

	// Test SHA512 with hex encoding
	sha512HexHash := GenerateSHA512HashHex(password)
	if !strings.HasPrefix(sha512HexHash, "{SHA512.HEX}") {
		t.Errorf("SHA512.HEX hash doesn't have the correct prefix: %s", sha512HexHash)
	}

	err = verifyPassword(sha512HexHash, password)
	if err != nil {
		t.Errorf("SHA512.HEX verification failed for correct password: %v", err)
	}

	err = verifyPassword(sha512HexHash, "wrongPassword")
	if err == nil {
		t.Error("SHA512.HEX verification should fail for incorrect password")
	}

	// Test with malformed hash
	err = verifyPassword("unknown_scheme_hash", password)
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
			err = verifySSHA512(hash, password)
			if err != nil {
				t.Errorf("Verification failed for correct password: %v", err)
			}

			// Test wrong password
			err = verifySSHA512(hash, "wrongPassword")
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
			err = verifySSHA512(hash2, password)
			if err != nil {
				t.Errorf("Second hash verification failed for correct password: %v", err)
			}
		})
	}

	// Test malformed SSHA512 hash
	err := verifySSHA512("{SSHA512}invalidBase64", password)
	if err == nil {
		t.Error("Verification should fail for malformed hash")
	}

	// Test with invalid format prefix
	err = verifySSHA512("{INVALID}hash", password)
	if err == nil {
		t.Error("Verification should fail for invalid format prefix")
	}

	// Test with too short hash
	shortHash := "{SSHA512}" + base64.StdEncoding.EncodeToString([]byte("tooshort"))
	err = verifySSHA512(shortHash, password)
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
			err := verifySHA512(hash, password)
			if err != nil {
				t.Errorf("Verification failed for correct password: %v", err)
			}

			// Test wrong password
			err = verifySHA512(hash, "wrongPassword")
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
	err := verifySHA512("{SHA512}invalidBase64", password)
	if err == nil {
		t.Error("Verification should fail for malformed hash")
	}

	// Test with invalid format prefix
	err = verifySHA512("{INVALID}hash", password)
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
	err := verifyPassword(b64Hash, password)
	if err != nil {
		t.Errorf("Manually created SHA512 base64 hash verification failed: %v", err)
	}

	// Encode with hex
	hexHash := "{SHA512.HEX}" + hex.EncodeToString(hash)
	err = verifyPassword(hexHash, password)
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
	err = verifyPassword(b64SSHA, password)
	if err != nil {
		t.Errorf("Manually created SSHA512 base64 hash verification failed: %v", err)
	}

	// Combine hash and salt, then encode with hex
	hexSSHA := "{SSHA512.HEX}" + hex.EncodeToString(combined)
	err = verifyPassword(hexSSHA, password)
	if err != nil {
		t.Errorf("Manually created SSHA512 hex hash verification failed: %v", err)
	}
}
