package idgen

import (
	"regexp"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	// Generate a new ID
	id := New()

	// Check that the ID is the correct length (approx 20 base32 characters)
	expectedLen := 20
	if len(id) != expectedLen {
		t.Errorf("Expected ID length to be %d, got %d", expectedLen, len(id))
	}

	// Verify the ID format using a regex pattern for base32 lowercase
	pattern := `^[a-z2-7]+$`
	matched, err := regexp.MatchString(pattern, id)
	if err != nil {
		t.Fatalf("Error matching regex: %v", err)
	}
	if !matched {
		t.Errorf("ID format does not match expected pattern: %s", id)
	}
}

func TestString(t *testing.T) {
	// Verify that String() and New() have the same behavior
	id1 := New()
	id2 := String()

	// Both should be valid IDs matching our format
	expectedLen := 20
	if len(id1) != expectedLen || len(id2) != expectedLen {
		t.Errorf("IDs should be %d characters long: %s, %s", expectedLen, id1, id2)
	}
}

func TestUniqueness(t *testing.T) {
	// Generate a large number of IDs and verify they're all unique
	count := 10000
	ids := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		id := New()
		if _, exists := ids[id]; exists {
			t.Errorf("Duplicate ID found: %s", id)
		}
		ids[id] = struct{}{}
	}
}

func TestConcurrentGeneration(t *testing.T) {
	// Test concurrent ID generation
	count := 1000
	ids := make([]string, count)
	var wg sync.WaitGroup
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func(index int) {
			defer wg.Done()
			ids[index] = New()
		}(i)
	}

	wg.Wait()

	// Check uniqueness
	uniqueIDs := make(map[string]struct{}, count)
	for _, id := range ids {
		if _, exists := uniqueIDs[id]; exists {
			t.Errorf("Duplicate ID found in concurrent generation: %s", id)
		}
		uniqueIDs[id] = struct{}{}
	}
}

func BenchmarkIDGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}
