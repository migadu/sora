package db

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestNeedsRehashDovecotSpellings: a bcrypt hash in any spelling VerifyPassword
// accepts is brought to BcryptCost after a login, like {BLF-CRYPT} and bare bcrypt
// hashes are. Dovecot generates BLF-CRYPT and CRYPT at cost 5
// (password-scheme-crypt.c, CRYPT_BLF_ROUNDS_DEFAULT).
func TestNeedsRehashDovecotSpellings(t *testing.T) {
	pinBcryptCost(t, bcrypt.MinCost+1)
	low, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	current, err := bcrypt.GenerateFromPassword([]byte("pw"), BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	for hash, want := range map[string]bool{
		"{blf-crypt}" + string(low):     true,
		"{CRYPT}$2y$" + string(low[4:]): true,
		"{crypt}" + string(low):         true,
		"{Blf-Crypt}" + string(current): false,
		"{CRYPT}" + string(current):     false,
	} {
		if got := NeedsRehash(hash); got != want {
			t.Errorf("NeedsRehash(%q) = %v, want %v (BcryptCost %d)", hash, got, want, BcryptCost)
		}
	}
}
