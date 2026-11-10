package imap

import (
	"maps"
	"slices"

	"github.com/emersion/go-imap/v2"
)

// copyUIDMapping turns a source UID → destination UID map into the COPYUID mapping
// (RFC 4315 §3): the nth source UID was copied to the nth destination UID. The pairs
// are listed by ascending source UID, which keeps the response deterministic and as
// short as the pairing allows; neither side is ever sorted on its own.
func copyUIDMapping(uidMap map[imap.UID]imap.UID) imap.UIDMapping {
	var mapping imap.UIDMapping
	for _, sourceUID := range slices.Sorted(maps.Keys(uidMap)) {
		mapping.Add(sourceUID, uidMap[sourceUID])
	}
	return mapping
}
