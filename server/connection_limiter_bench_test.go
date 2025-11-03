package server

import (
	"net"
	"sync"
	"testing"
)

// BenchmarkConnectionLimiterAccept benchmarks concurrent connection acceptance
func BenchmarkConnectionLimiterAccept(b *testing.B) {
	limiter := NewConnectionLimiter("test", 10000, 50)
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			release, err := limiter.AcceptWithRealIP(addr, "")
			if err != nil {
				b.Fatal(err)
			}
			release()
		}
	})
}

// BenchmarkConnectionLimiterAcceptHighContention simulates high contention with many IPs
func BenchmarkConnectionLimiterAcceptHighContention(b *testing.B) {
	limiter := NewConnectionLimiter("test", 10000, 50)

	// Create 100 different IPs to simulate realistic proxy load
	addrs := make([]*net.TCPAddr, 100)
	for i := 0; i < 100; i++ {
		addrs[i] = &net.TCPAddr{
			IP:   net.ParseIP("192.168.1." + string(rune(i+1))),
			Port: 12345,
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			addr := addrs[i%len(addrs)]
			i++
			release, err := limiter.AcceptWithRealIP(addr, "")
			if err != nil {
				b.Fatal(err)
			}
			release()
		}
	})
}

// BenchmarkConnectionLimiterConcurrentOperations tests mixed operations under load
func BenchmarkConnectionLimiterConcurrentOperations(b *testing.B) {
	limiter := NewConnectionLimiter("test", 10000, 50)
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// Pre-populate with some connections
	var releases []func()
	for i := 0; i < 10; i++ {
		release, _ := limiter.AcceptWithRealIP(addr, "")
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	b.ResetTimer()
	var wg sync.WaitGroup

	// Simulate accept operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			release, err := limiter.AcceptWithRealIP(addr, "")
			if err != nil {
				continue
			}
			release()
		}
	}()

	// Simulate stats queries (concurrent readers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N/10; i++ {
			_ = limiter.GetStats()
		}
	}()

	wg.Wait()
}
