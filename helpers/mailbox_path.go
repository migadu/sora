package helpers

import (
	"fmt"
	"strconv"
	"strings"
)

// The size of each ID in the path (16 hexadecimal characters representing an int64)
const HexIDLength = 16

// FormatMailboxID converts a mailbox ID to a fixed-length hex representation
func FormatMailboxID(id int64) string {
	return fmt.Sprintf("%016x", id)
}

// ParseMailboxIDFromHex extracts a mailbox ID from a hex string
func ParseMailboxIDFromHex(hexID string) (int64, error) {
	if len(hexID) != HexIDLength {
		return 0, fmt.Errorf("invalid hex ID length: %d, expected %d", len(hexID), HexIDLength)
	}

	// Parse the hex string back to int64
	value, err := strconv.ParseInt(hexID, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to decode hex ID: %w", err)
	}

	return value, nil
}

// GetParentPathFromPath extracts the parent path from a full path
func GetParentPathFromPath(path string) string {
	if len(path) <= HexIDLength {
		// This is a root mailbox, it has no parent
		return ""
	}

	// Return everything except the last HexIDLength characters
	return path[:len(path)-HexIDLength]
}

// GetMailboxPath constructs a mailbox path from parent path and ID
func GetMailboxPath(parentPath string, id int64) string {
	hexID := FormatMailboxID(id)
	return parentPath + hexID
}

// GetIdsFromPath extracts all mailbox IDs from a path
func GetIdsFromPath(path string) ([]int64, error) {
	if path == "" {
		return []int64{}, nil
	}

	pathLen := len(path)
	if pathLen%HexIDLength != 0 {
		return nil, fmt.Errorf("invalid path length: %d is not a multiple of %d", pathLen, HexIDLength)
	}

	idCount := pathLen / HexIDLength
	ids := make([]int64, idCount)

	for i := 0; i < idCount; i++ {
		start := i * HexIDLength
		end := start + HexIDLength

		id, err := ParseMailboxIDFromHex(path[start:end])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID at position %d: %w", i, err)
		}

		ids[i] = id
	}

	return ids, nil
}

// IsDescendantOf checks if childPath is a descendant of parentPath
func IsDescendantOf(childPath, parentPath string) bool {
	// Empty parent path means root level, which is parent to all
	if parentPath == "" {
		return childPath != ""
	}

	// A path is a descendant if it starts with the parent path
	// and is longer than the parent path
	return len(childPath) > len(parentPath) && strings.HasPrefix(childPath, parentPath)
}

// IsDirectChildOf checks if childPath is a direct child of parentPath
func IsDirectChildOf(childPath, parentPath string) bool {
	// For direct child, the child path should be exactly parent path + one hex ID
	expectedChildLen := len(parentPath) + HexIDLength

	return len(childPath) == expectedChildLen && strings.HasPrefix(childPath, parentPath)
}

// Note: The FindCommonPath function is already defined in helpers/path.go
