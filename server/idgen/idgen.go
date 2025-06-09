package idgen

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// nodeID is a 3-byte identifier for this instance
	nodeID []byte
	// sequence is an atomically incremented counter to ensure uniqueness
	sequence uint32
	// base32Encoding is a modified version of base32 without padding
	base32Encoding = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)
)

// init initializes the node ID and other state for the ID generator
func init() {
	// Generate a 3-byte random node ID
	nodeID = make([]byte, 3)
	if _, err := rand.Read(nodeID); err != nil {
		// Fallback to hostname-based ID if random generation fails
		hostname, err := os.Hostname()
		if err != nil {
			// If all else fails, use a timestamp-based fallback
			now := time.Now().UnixNano()
			nodeID = []byte(fmt.Sprintf("%06x", now)[:6])
		} else {
			// Use first 3 bytes of hostname hash as node ID
			nodeHash := []byte(hostname)
			copy(nodeID, nodeHash)
			if len(nodeHash) < 3 {
				// Pad with zeros if hostname is too short
				for i := len(nodeHash); i < 3; i++ {
					nodeID[i] = 0
				}
			}
		}
	}
}

// New generates a new compact hybrid ID with the following format:
// - 4 bytes: timestamp (seconds since epoch, truncated)
// - 3 bytes: node ID
// - 2 bytes: atomically incremented sequence number
// - 3 bytes: random data
// Total: 12 bytes, encoded in base32 for ~20 characters
func New() string {
	// Get timestamp in seconds (using a 32-bit truncated value to save space)
	timestamp := uint32(time.Now().Unix())

	// Atomically increment sequence and use only 16 bits
	seq := atomic.AddUint32(&sequence, 1) & 0xFFFF

	// Generate 3 bytes of random data
	randomBytes := make([]byte, 3)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback if random generation fails
		randomBytes = []byte(fmt.Sprintf("%06x", time.Now().UnixNano())[:6])
	}

	// Construct the binary ID (12 bytes total)
	id := make([]byte, 12)

	// 4 bytes timestamp
	id[0] = byte(timestamp >> 24)
	id[1] = byte(timestamp >> 16)
	id[2] = byte(timestamp >> 8)
	id[3] = byte(timestamp)

	// 3 bytes node ID
	copy(id[4:7], nodeID)

	// 2 bytes sequence
	id[7] = byte(seq >> 8)
	id[8] = byte(seq)

	// 3 bytes random
	copy(id[9:12], randomBytes)

	// Encode as base32 for readability and compactness
	encoded := base32Encoding.EncodeToString(id)

	// Convert to lowercase for better readability
	return strings.ToLower(encoded)
}

// String alias for New for drop-in compatibility with uuid.New().String()
func String() string {
	return New()
}
