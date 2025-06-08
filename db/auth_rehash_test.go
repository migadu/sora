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
					cost = bcrypt.DefaultCost
				}
				hash, _ := bcrypt.GenerateFromPassword([]byte("password"), cost)
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
			result := needsRehash(hash)
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
		name           string
		hash           string
		expectedRehash bool
	}{
		{
			name: "Standard Bcrypt with Default Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				return string(hash)
			}(),
			expectedRehash: false,
		},
		{
			name: "Standard Bcrypt with Lower Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
				return string(hash)
			}(),
			expectedRehash: true,
		},
		{
			name: "BLF-CRYPT with Default Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				return "{BLF-CRYPT}" + string(hash)
			}(),
			expectedRehash: false,
		},
		{
			name: "BLF-CRYPT with Lower Cost",
			hash: func() string {
				hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
				return "{BLF-CRYPT}" + string(hash)
			}(),
			expectedRehash: true,
		},
		{
			name:           "SSHA512 Hash",
			hash:           "{SSHA512}xxxxxxxxxxxxxx",
			expectedRehash: false,
		},
		{
			name:           "SHA512 Hash",
			hash:           "{SHA512}xxxxxxxxxxxxxx",
			expectedRehash: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needsRehashing := needsRehash(tt.hash)
			if needsRehashing != tt.expectedRehash {
				t.Errorf("needsRehash(%q) = %v, want %v", tt.hash, needsRehashing, tt.expectedRehash)
			}

			// If rehashing is needed, test that we can create a new hash that doesn't need rehashing
			if tt.expectedRehash {
				// Regenerate hash with default cost
				var newHash string
				if strings.HasPrefix(tt.hash, "{BLF-CRYPT}") {
					newHashBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
					newHash = "{BLF-CRYPT}" + string(newHashBytes)
				} else {
					newHashBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
					newHash = string(newHashBytes)
				}

				// New hash should not need rehashing
				if needsRehash(newHash) {
					t.Errorf("Newly generated hash still needs rehashing: %s", newHash)
				}
			}
		})
	}
}
