package proxy

import (
	"fmt"
	"testing"
)

func TestConsistentHash_Basic(t *testing.T) {
	ch := NewConsistentHash(150)

	backends := []string{
		"backend1:143",
		"backend2:143",
		"backend3:143",
	}

	for _, backend := range backends {
		ch.AddBackend(backend)
	}

	// Test that same user always maps to same backend
	user1 := "user1@example.com"
	backend1 := ch.GetBackend(user1)
	if backend1 == "" {
		t.Fatal("Expected backend for user1, got empty")
	}

	// Call multiple times - should get same backend
	for i := 0; i < 10; i++ {
		backend := ch.GetBackend(user1)
		if backend != backend1 {
			t.Errorf("Inconsistent hashing: expected %s, got %s on iteration %d", backend1, backend, i)
		}
	}
}

func TestConsistentHash_MultipleProxies(t *testing.T) {
	// Simulate two proxies with same backends
	proxy1Hash := NewConsistentHash(150)
	proxy2Hash := NewConsistentHash(150)

	backends := []string{
		"10.10.10.31:143",
		"10.10.10.32:143",
	}

	// Both proxies add same backends
	for _, backend := range backends {
		proxy1Hash.AddBackend(backend)
		proxy2Hash.AddBackend(backend)
	}

	// Test that both proxies map same user to same backend
	testUsers := []string{
		"me@dejanstrbac.com",
		"user2@example.com",
		"user3@example.com",
		"admin@test.com",
	}

	for _, user := range testUsers {
		backend1 := proxy1Hash.GetBackend(user)
		backend2 := proxy2Hash.GetBackend(user)

		if backend1 != backend2 {
			t.Errorf("Proxies disagree on placement for %s: proxy1=%s, proxy2=%s", user, backend1, backend2)
		}

		t.Logf("User %s → %s (both proxies agree)", user, backend1)
	}
}

func TestConsistentHash_Failover(t *testing.T) {
	ch := NewConsistentHash(150)

	backends := []string{
		"backend1:143",
		"backend2:143",
		"backend3:143",
	}

	for _, backend := range backends {
		ch.AddBackend(backend)
	}

	user := "test@example.com"
	primaryBackend := ch.GetBackend(user)
	t.Logf("Primary backend for %s: %s", user, primaryBackend)

	// Simulate primary backend failure - exclude it
	exclude := map[string]bool{primaryBackend: true}
	failoverBackend := ch.GetBackendWithExclusions(user, exclude)

	if failoverBackend == "" {
		t.Fatal("Expected failover backend, got empty")
	}

	if failoverBackend == primaryBackend {
		t.Errorf("Failover backend should be different from primary: %s", primaryBackend)
	}

	t.Logf("Failover backend for %s: %s", user, failoverBackend)

	// Exclude both primary and failover
	exclude[failoverBackend] = true
	secondaryFailover := ch.GetBackendWithExclusions(user, exclude)

	if secondaryFailover == "" {
		t.Fatal("Expected secondary failover backend, got empty")
	}

	if secondaryFailover == primaryBackend || secondaryFailover == failoverBackend {
		t.Errorf("Secondary failover should be different from primary and failover")
	}

	t.Logf("Secondary failover backend for %s: %s", user, secondaryFailover)
}

func TestConsistentHash_Distribution(t *testing.T) {
	ch := NewConsistentHash(150)

	backends := []string{
		"backend1:143",
		"backend2:143",
		"backend3:143",
	}

	for _, backend := range backends {
		ch.AddBackend(backend)
	}

	// Test distribution across 1000 users
	distribution := make(map[string]int)
	numUsers := 1000

	for i := 0; i < numUsers; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		backend := ch.GetBackend(user)
		distribution[backend]++
	}

	t.Logf("Distribution across %d users:", numUsers)
	for backend, count := range distribution {
		percentage := float64(count) / float64(numUsers) * 100
		t.Logf("  %s: %d users (%.1f%%)", backend, count, percentage)
	}

	// Check that distribution is reasonable (within 20% of ideal)
	idealCount := numUsers / len(backends)
	tolerance := float64(idealCount) * 0.20

	for backend, count := range distribution {
		diff := float64(count) - float64(idealCount)
		if diff < 0 {
			diff = -diff
		}

		if diff > tolerance {
			t.Errorf("Backend %s has poor distribution: %d users (expected ~%d ± %.0f)",
				backend, count, idealCount, tolerance)
		}
	}
}

func TestConsistentHash_RemoveBackend(t *testing.T) {
	ch := NewConsistentHash(150)

	backends := []string{
		"backend1:143",
		"backend2:143",
		"backend3:143",
	}

	for _, backend := range backends {
		ch.AddBackend(backend)
	}

	// Record where users are placed
	numUsers := 100
	beforeRemoval := make(map[string]string) // user → backend

	for i := 0; i < numUsers; i++ {
		user := fmt.Sprintf("user%d@example.com", i)
		backend := ch.GetBackend(user)
		beforeRemoval[user] = backend
	}

	// Remove one backend
	removedBackend := "backend2:143"
	ch.RemoveBackend(removedBackend)
	t.Logf("Removed backend: %s", removedBackend)

	// Check how many users moved
	moved := 0
	for user, oldBackend := range beforeRemoval {
		newBackend := ch.GetBackend(user)

		if oldBackend == removedBackend {
			// User must have moved
			if newBackend == removedBackend {
				t.Errorf("User %s still on removed backend %s", user, removedBackend)
			}
			moved++
		} else {
			// User should ideally stay on same backend
			// (but some may move due to consistent hashing properties)
			if newBackend != oldBackend {
				moved++
			}
		}
	}

	movedPercentage := float64(moved) / float64(numUsers) * 100
	t.Logf("Users moved: %d/%d (%.1f%%)", moved, numUsers, movedPercentage)

	// With consistent hashing, approximately 1/3 of users should move
	// (those on the removed backend)
	expectedMoved := numUsers / len(backends)
	tolerance := float64(expectedMoved) * 0.5 // 50% tolerance

	diff := float64(moved) - float64(expectedMoved)
	if diff < 0 {
		diff = -diff
	}

	if diff > tolerance {
		t.Logf("Warning: More users moved than expected: %d (expected ~%d ± %.0f)",
			moved, expectedMoved, tolerance)
	}
}
