package lookupcache

import (
	"sync"
	"testing"
	"time"
)

func TestLookupCache_DataRace_Get_Refresh(t *testing.T) {
	cache := New(time.Minute, time.Minute, 100, time.Minute, time.Minute)
	server := "server1"
	user := "user1"

	// Setup initial entry
	cache.SetSuccess(makeKey(server, user), 1, "hash", "pass")

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})

	// Goroutine 1: Continuously Refresh
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				cache.Refresh(server, user)
			}
		}
	}()

	// Goroutine 2: Continuously Get
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				cache.Get(server, user)
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(done)
	wg.Wait()
}

func TestLookupCache_DataRace_GetOrFetch_Refresh(t *testing.T) {
	cache := New(time.Minute, time.Minute, 100, time.Minute, time.Minute)
	server := "server1"
	user := "user1"

	// Setup initial entry
	cache.SetSuccess(makeKey(server, user), 1, "hash", "pass")

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})

	// Goroutine 1: Continuously Refresh
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				cache.Refresh(server, user)
			}
		}
	}()

	// Goroutine 2: Continuously GetOrFetch
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				cache.GetOrFetch(server, user, func() (*CacheEntry, error) {
					return &CacheEntry{
						AccountID: 1,
						Result:    AuthSuccess,
						CreatedAt: time.Now(),
						ExpiresAt: time.Now().Add(time.Minute),
					}, nil
				})
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(done)
	wg.Wait()
}
