package db

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNeedsRehash(t *testing.T) {
	// Test cases for different cost bcrypt hashes
	tests := []struct {
		name        string
		hashCreator func() string
		needsRehash bool
	}{
		{
			name: "Default Cost Bcrypt",
			hashCreator: func() string {
				// Generate bcrypt with default cost
				hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
				return string(hash)
			},
			needsRehash: false,
		},
		{
			name: "Lower Cost Bcrypt",
			hashCreator: func() string {
				// Generate bcrypt with lower cost
				hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost-1)
				return string(hash)
			},
			needsRehash: true,
		},
		{
			name: "Higher Cost Bcrypt",
			hashCreator: func() string {
				// Generate bcrypt with higher cost (if possible)
				cost := bcrypt.DefaultCost + 1
				if cost > bcrypt.MaxCost {
					t.Skipf("Cannot test with higher cost; DefaultCost (%d) is too close to MaxCost (%d)", bcrypt.DefaultCost, bcrypt.MaxCost)
				}
				hash, err := bcrypt.GenerateFromPassword([]byte("password"), cost)
				if err != nil {
					t.Fatalf("Failed to generate higher cost hash: %v", err)
				}
				return string(hash)
			},
			needsRehash: true,
		},
		{
			name: "BLF-CRYPT Default Cost",
			hashCreator: func() string {
				// Generate bcrypt with default cost
				hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
				return "{BLF-CRYPT}" + string(hash)
			},
			needsRehash: false,
		},
		{
			name: "BLF-CRYPT Lower Cost",
			hashCreator: func() string {
				// Generate bcrypt with lower cost
				hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost-1)
				return "{BLF-CRYPT}" + string(hash)
			},
			needsRehash: true,
		},
		{
			name: "SSHA512 Hash",
			hashCreator: func() string {
				hash, _ := GenerateSSHA512Hash("password")
				return hash
			},
			needsRehash: false, // SSHA512 doesn't need rehashing
		},
		{
			name: "SHA512 Hash",
			hashCreator: func() string {
				return GenerateSHA512Hash("password")
			},
			needsRehash: false, // SHA512 doesn't need rehashing
		},
		{
			name: "Invalid Format",
			hashCreator: func() string {
				return "invalid_hash_format"
			},
			needsRehash: false, // Unknown format, no rehashing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.hashCreator()
			result := NeedsRehash(hash)
			if result != tt.needsRehash {
				t.Errorf("needsRehash(%q) = %v, want %v", hash, result, tt.needsRehash)
			}
		})
	}
}

// Test the needsRehash function directly without mocking the database

func TestRehashOperation(t *testing.T) {
	// Test the password rehashing directly
	password := "testPassword123"

	tests := []struct {
		name        string
		hash        string
		needsRehash bool
	}{
		{
			name: "Standard Bcrypt with Default Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				return string(hash)
			}(),
			needsRehash: false,
		},
		{
			name: "Standard Bcrypt with Lower Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
				return string(hash)
			}(),
			needsRehash: true,
		},
		{
			name: "BLF-CRYPT with Default Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				return "{BLF-CRYPT}" + string(hash)
			}(),
			needsRehash: false,
		},
		{
			name: "BLF-CRYPT with Lower Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
				return "{BLF-CRYPT}" + string(hash)
			}(),
			needsRehash: true,
		},
		{
			name: "SSHA512 Hash",
			hash: func() string {
				hash, _ := GenerateSSHA512Hash(password)
				return hash
			}(),
			needsRehash: false,
		},
		{
			name: "SHA512 Hash",
			hash: func() string {
				return GenerateSHA512Hash(password)
			}(),
			needsRehash: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needsRehashing := NeedsRehash(tt.hash)
			if needsRehashing != tt.needsRehash {
				t.Errorf("NeedsRehash() = %v, want %v", needsRehashing, tt.needsRehash)
			}

			// If rehashing is needed, test that we can create a new hash that doesn't need rehashing
			if tt.needsRehash {
				newHashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					t.Fatalf("Failed to generate default cost hash: %v", err)
				}
				newHash := string(newHashBytes)
				if strings.HasPrefix(tt.hash, "{BLF-CRYPT}") {
					newHash = "{BLF-CRYPT}" + newHash
				}

				// New hash should not need rehashing
				if NeedsRehash(newHash) {
					t.Errorf("Newly generated hash still needs rehashing: %s", newHash)
				}
			}
		})
	}
}
