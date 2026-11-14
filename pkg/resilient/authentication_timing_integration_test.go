//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"golang.org/x/crypto/bcrypt"
)

// mapAuthCache stands in for the proxies' persistent auth cache (authcache.Cache).
type mapAuthCache struct {
	mu      sync.Mutex
	entries map[string]mapAuthCacheEntry
}

type mapAuthCacheEntry struct {
	accountID int64
	hash      string
}

func (c *mapAuthCache) Get(_ context.Context, address string) (int64, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[address]
	if !ok {
		return 0, "", errors.New("not cached")
	}
	return e.accountID, e.hash, nil
}

func (c *mapAuthCache) Put(_ context.Context, address string, accountID int64, hash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[address] = mapAuthCacheEntry{accountID: accountID, hash: hash}
	return nil
}

func (c *mapAuthCache) Invalidate(_ context.Context, address string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, address)
	return nil
}

func (c *mapAuthCache) InvalidateAccount(_ context.Context, accountID int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for address, e := range c.entries {
		if e.accountID == accountID {
			delete(c.entries, address)
		}
	}
	return nil
}

// TestAuthenticateWithRetry_FailedLoginTimingHidesAccountExistence covers the database
// login of the IMAP, POP3 and ManageSieve proxies (#346). A failed login must take about
// as long whether or not the address has an account, as on the backends, or response time
// tells an attacker which addresses exist. A login fails in one of three ways here: the
// address has no account; it has one and the password is wrong; or it has one whose hash
// the auth cache holds and the password is wrong. Each must cost one password verification.
func TestAuthenticateWithRetry_FailedLoginTimingHidesAccountExistence(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	pool := newTestPool(t, cfg, nil)
	rd := newTestResilientDatabase(cfg, pool)
	cache := &mapAuthCache{entries: map[string]mapAuthCacheEntry{}}
	rd.SetAuthCache(cache)

	// Cost 10 keeps one verification in the tens of milliseconds, far above a local
	// query and scheduler noise. The timing dummy hash follows BcryptCost.
	origCost := db.BcryptCost
	db.BcryptCost = 10
	t.Cleanup(func() { db.BcryptCost = origCost })

	hash, err := bcrypt.GenerateFromPassword([]byte("the-real-password"), db.BcryptCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	suffix := time.Now().UnixNano()
	known := fmt.Sprintf("timing-known-%d@example.com", suffix)
	unknown := fmt.Sprintf("timing-unknown-%d@example.com", suffix)

	var accountID int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM credentials WHERE account_id = $1`, accountID)
		pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO credentials (account_id, address, password, primary_identity) VALUES ($1, $2, $3, true)`,
		accountID, known, string(hash)); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	logins := []struct {
		name    string
		prepare func()
		address string
		wantErr error
	}{
		{"unknown address", func() {}, unknown, consts.ErrUserNotFound},
		{"wrong password", func() { cache.Invalidate(ctx, known) }, known, bcrypt.ErrMismatchedHashAndPassword},
		{"wrong password, hash in auth cache", func() { cache.Put(ctx, known, accountID, string(hash)) }, known, bcrypt.ErrMismatchedHashAndPassword},
	}
	const baseline = 1 // "wrong password": what the backends cost every failed login

	login := func(i int) time.Duration {
		l := logins[i]
		l.prepare()
		start := time.Now()
		_, err := rd.AuthenticateWithRetry(ctx, l.address, "wrong-password")
		elapsed := time.Since(start)
		if !errors.Is(err, l.wantErr) {
			t.Fatalf("%s: AuthenticateWithRetry error = %v, want %v", l.name, err, l.wantErr)
		}
		return elapsed
	}

	// Warm up the pool connection and the lazily generated dummy hash.
	for i := range logins {
		login(i)
	}

	// Interleave the kinds and keep each one's fastest run: load only ever adds time.
	// A divergent round is retried, since a real regression (a skipped verification,
	// or a second one) diverges in every round and noise does not.
	const rounds, reps = 5, 5
	var fastest []time.Duration
	for round := 1; round <= rounds; round++ {
		fastest = make([]time.Duration, len(logins))
		for i := range fastest {
			fastest[i] = time.Duration(1 << 62)
		}
		for rep := 0; rep < reps; rep++ {
			for i := range logins {
				fastest[i] = min(fastest[i], login(i))
			}
		}

		diverged := ""
		for i, l := range logins {
			if ratio := float64(fastest[i]) / float64(fastest[baseline]); ratio < 2.0/3 || ratio > 1.5 {
				diverged += fmt.Sprintf("; %s took %v against %v for %s (ratio %.2f, want 0.67-1.5)",
					l.name, fastest[i], fastest[baseline], logins[baseline].name, ratio)
			}
		}
		if diverged == "" {
			return
		}
		if round == rounds {
			t.Fatalf("failed logins are distinguishable by response time in all %d rounds%s", rounds, diverged)
		}
		t.Logf("round %d diverged%s; retrying", round, diverged)
	}
}
