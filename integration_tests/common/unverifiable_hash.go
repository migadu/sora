//go:build integration

package common

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// StoreUnverifiableHash replaces the stored hash of address with a Dovecot {SSHA256}
// hash of password: correct for the password, but in a scheme sora does not verify
// (db.ErrUnverifiableHash), as a legacy row or a direct SQL write may hold. The
// returned func puts the original hash back, as an administrator repairing the
// credential would.
func StoreUnverifiableHash(t *testing.T, rdb *resilient.ResilientDatabase, address, password string) (repair func()) {
	t.Helper()
	ctx := context.Background()

	_, original, err := rdb.GetCredentialForAuthWithRetry(ctx, address)
	if err != nil {
		t.Fatalf("read the stored hash of %s: %v", address, err)
	}

	salt := []byte("saltsalt")
	digest := sha256.Sum256(append([]byte(password), salt...))
	hash := "{SSHA256}" + base64.StdEncoding.EncodeToString(append(digest[:], salt...))
	if err := db.ValidatePasswordHash(hash); !errors.Is(err, db.ErrUnverifiableHash) {
		t.Fatalf("ValidatePasswordHash(%q) = %v, want db.ErrUnverifiableHash", hash, err)
	}
	if err := rdb.UpdatePasswordWithRetry(ctx, address, hash); err != nil {
		t.Fatalf("store an unverifiable hash for %s: %v", address, err)
	}

	return func() {
		t.Helper()
		if err := rdb.UpdatePasswordWithRetry(ctx, address, original); err != nil {
			t.Fatalf("restore the stored hash of %s: %v", address, err)
		}
	}
}
