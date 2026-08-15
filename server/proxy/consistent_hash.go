package proxy

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sort"
	"strconv"
	"sync"
)

// ConsistentHash implements consistent hashing with virtual nodes for even distribution
type ConsistentHash struct {
	ring         map[uint64]string // hash → backend address
	sortedHashes []uint64          // sorted hash values
	backends     []string          // backend addresses, kept sorted
	virtualNodes int               // number of virtual nodes per backend
	mu           sync.RWMutex
}

// NewConsistentHash creates a new consistent hash ring
// virtualNodes: number of virtual nodes per backend (typically 150-500 for even distribution)
func NewConsistentHash(virtualNodes int) *ConsistentHash {
	if virtualNodes <= 0 {
		virtualNodes = 150 // Default: good balance between distribution and memory
	}

	return &ConsistentHash{
		ring:         make(map[uint64]string),
		sortedHashes: make([]uint64, 0),
		backends:     make([]string, 0),
		virtualNodes: virtualNodes,
	}
}

// AddBackend adds a backend to the hash ring with virtual nodes
func (ch *ConsistentHash) AddBackend(backend string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	idx := sort.SearchStrings(ch.backends, backend)
	if idx < len(ch.backends) && ch.backends[idx] == backend {
		return
	}

	ch.backends = append(ch.backends, "")
	copy(ch.backends[idx+1:], ch.backends[idx:])
	ch.backends[idx] = backend

	ch.rebuild()
}

// RemoveBackend removes a backend from the hash ring
func (ch *ConsistentHash) RemoveBackend(backend string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	idx := sort.SearchStrings(ch.backends, backend)
	if idx >= len(ch.backends) || ch.backends[idx] != backend {
		return
	}

	ch.backends = append(ch.backends[:idx], ch.backends[idx+1:]...)

	ch.rebuild()
}

// rebuild recomputes the ring from the current backend set. Placement depends only on
// that set, never on the order AddBackend/RemoveBackend was called in, so every proxy
// derives the same ring from the same pool across restarts.
func (ch *ConsistentHash) rebuild() {
	ch.ring = make(map[uint64]string, len(ch.backends)*ch.virtualNodes)
	ch.sortedHashes = make([]uint64, 0, len(ch.backends)*ch.virtualNodes)

	occurrences := make(map[string]int, len(ch.backends))

	for _, backend := range ch.backends {
		host := backendHost(backend)
		occurrence := occurrences[host]
		occurrences[host]++

		for i := 0; i < ch.virtualNodes; i++ {
			hash := ch.hash(backend, occurrence, i)
			ch.ring[hash] = backend
			ch.sortedHashes = append(ch.sortedHashes, hash)
		}
	}

	sort.Slice(ch.sortedHashes, func(i, j int) bool {
		return ch.sortedHashes[i] < ch.sortedHashes[j]
	})
}

// GetBackend returns the backend for a given key (username)
// Returns empty string if no backends are available
func (ch *ConsistentHash) GetBackend(key string) string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if len(ch.sortedHashes) == 0 {
		return ""
	}

	hash := ch.hashKey(key)

	// Binary search for the first hash >= key hash
	idx := sort.Search(len(ch.sortedHashes), func(i int) bool {
		return ch.sortedHashes[i] >= hash
	})

	// Wrap around if we're past the end
	if idx >= len(ch.sortedHashes) {
		idx = 0
	}

	return ch.ring[ch.sortedHashes[idx]]
}

// GetBackendWithExclusions returns a backend for a key, excluding specified backends
// This is useful for failover: if primary backend fails, get the next one
func (ch *ConsistentHash) GetBackendWithExclusions(key string, exclude map[string]bool) string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if len(ch.sortedHashes) == 0 {
		return ""
	}

	hash := ch.hashKey(key)

	// Binary search for the first hash >= key hash
	startIdx := sort.Search(len(ch.sortedHashes), func(i int) bool {
		return ch.sortedHashes[i] >= hash
	})

	// Try all positions in the ring (wrapping around)
	for i := 0; i < len(ch.sortedHashes); i++ {
		idx := (startIdx + i) % len(ch.sortedHashes)
		backend := ch.ring[ch.sortedHashes[idx]]

		if !exclude[backend] {
			return backend
		}
	}

	// All backends excluded
	return ""
}

// GetAllBackends returns all unique backends in the ring
func (ch *ConsistentHash) GetAllBackends() []string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	backends := make([]string, len(ch.backends))
	copy(backends, ch.backends)

	return backends
}

// backendHost strips the port from a backend address, if it has one
func backendHost(backend string) string {
	if host, _, err := net.SplitHostPort(backend); err == nil {
		return host
	}
	return backend
}

// hash generates a hash for a backend and virtual node index.
// Uses only the hostname (without port) so all protocol proxies (IMAP :143, POP3 :110,
// LMTP :24, etc.) produce identical ring positions for the same backend machines.
// This ensures cross-protocol cache locality: the same user maps to the same machine
// regardless of which protocol proxy handles the connection.
// occurrence separates several backends sharing one host; occurrence 0 hashes by the
// bare hostname, so a host running a single instance keeps that cross-protocol position.
func (ch *ConsistentHash) hash(backend string, occurrence, vnodeIndex int) uint64 {
	hashKey := backendHost(backend)
	if occurrence > 0 {
		hashKey += "#" + strconv.Itoa(occurrence)
	}

	h := sha256.New()
	h.Write([]byte(hashKey))
	// Add virtual node index to distribute virtual nodes around ring
	h.Write([]byte{byte(vnodeIndex >> 24), byte(vnodeIndex >> 16), byte(vnodeIndex >> 8), byte(vnodeIndex)})
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// hashKey generates a hash for a key (username)
func (ch *ConsistentHash) hashKey(key string) uint64 {
	h := sha256.New()
	h.Write([]byte(key))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// Size returns the number of backends in the ring
func (ch *ConsistentHash) Size() int {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	return len(ch.backends)
}
