package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestQueueRehash_PanicRecovery verifies that a panic inside the rehash function is
// recovered rather than crashing the whole process. The rehash runs in a detached
// goroutine, so without recover() an unrecovered panic would take the binary down —
// the same failure mode as the C1 POP3 fix. It also confirms the concurrency permit
// is released during the panic unwind, so a subsequent rehash still runs.
func TestQueueRehash_PanicRecovery(t *testing.T) {
	// 1) A panicking rehash must not crash the test binary.
	started := make(chan struct{})
	QueueRehash("panic-key", func(ctx context.Context) {
		close(started)
		panic("boom in rehash")
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("panicking rehash never ran")
	}
	// Let the deferred recover unwind in the rehash goroutine. If recovery were
	// missing, the unrecovered panic would already have killed the binary.
	time.Sleep(50 * time.Millisecond)

	// 2) A subsequent rehash must still execute — proves the semaphore permit was
	// released while the panic unwound (the deferred release ran).
	done := make(chan struct{})
	QueueRehash("ok-key", func(ctx context.Context) {
		close(done)
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("subsequent rehash did not run (permit leaked on panic?)")
	}
}

// TestQueueRehash_LoadShedding verifies that when the rehash concurrency limit is
// saturated, a further rehash is shed (dropped) rather than queued. A shed rehash
// must NOT run even after the in-flight rehashes release their permits — that's what
// distinguishes load-shedding from blocking-then-running.
func TestQueueRehash_LoadShedding(t *testing.T) {
	capN := cap(rehashSemaphore)
	release := make(chan struct{})
	var holding sync.WaitGroup
	holding.Add(capN)

	// Saturate every permit with a rehash that blocks until released (distinct keys so
	// singleflight doesn't dedup them).
	for i := 0; i < capN; i++ {
		QueueRehash(fmt.Sprintf("hold-%d", i), func(ctx context.Context) {
			holding.Done()
			<-release
		})
	}
	holding.Wait() // all permits now held

	// This one must be shed.
	ran := make(chan struct{}, 1)
	QueueRehash("shed-key", func(ctx context.Context) {
		ran <- struct{}{}
	})
	time.Sleep(100 * time.Millisecond) // time to shed (or, if broken, to block)

	// Free the permits. If shed-key had QUEUED, it would now acquire one and run.
	close(release)
	time.Sleep(200 * time.Millisecond)

	select {
	case <-ran:
		t.Error("rehash ran after permits were freed — it was queued, not shed")
	default:
		// expected: shed immediately, never ran
	}
}
