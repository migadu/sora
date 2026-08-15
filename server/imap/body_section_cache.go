package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
)

// A session retains the last body section it fully extracted so that a client pulling
// one part in <offset.size> chunks does not reload the message and re-extract the part
// for every chunk. The retention is bounded three ways:
//
//   - one section per session, dropped as soon as another section is retained, the
//     mailbox selection is cleared, or the client goes into IDLE;
//   - maxCachedBodySectionBytes for that one section;
//   - maxServerBodySectionCacheBytes for all sessions on this node together.
//
// The retained bytes are charged to the session memory tracker for as long as they are
// held, and memoryAvailable gives them back rather than let them starve a later fetch.
const (
	maxCachedBodySectionBytes      = 8 << 20
	maxServerBodySectionCacheBytes = 256 << 20
)

// bodySectionCacheKey identifies a body section independently of its <offset.size>
// slice, so successive chunk requests for the same section share one entry. It returns
// an empty key for a message without a content hash, which disables the cache: without
// the hash there is nothing that ties the retained bytes to the message.
func bodySectionCacheKey(contentHash string, section *imap.FetchItemBodySection) string {
	if contentHash == "" {
		return ""
	}
	return fmt.Sprintf("%s|%s|%v|%v|%v", contentHash, section.Specifier, section.Part,
		section.HeaderFields, section.HeaderFieldsNot)
}

// cachedBodySection returns the retained section for key, or nil.
func (s *IMAPSession) cachedBodySection(key string) []byte {
	if key == "" {
		return nil
	}
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	if s.bodySectionCacheKey != key {
		return nil
	}
	return s.bodySectionCacheData
}

// retainBodySection keeps data as this session's single cached section. When it reports
// true it has taken over the caller's memory-tracker charge for data, which
// releaseBodySectionCache gives back.
func (s *IMAPSession) retainBodySection(key string, data []byte) bool {
	if key == "" || len(data) == 0 || len(data) > maxCachedBodySectionBytes {
		return false
	}

	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()

	s.dropRetainedLocked()
	if !s.server.reserveBodySectionCacheBytes(int64(len(data))) {
		return false
	}
	s.bodySectionCacheKey = key
	s.bodySectionCacheData = data
	return true
}

// releaseBodySectionCache drops the retained section and gives back both the node-wide
// reservation and the session memory charge it carried.
func (s *IMAPSession) releaseBodySectionCache() {
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	s.dropRetainedLocked()
}

// dropRetainedLocked forgets the retained section and gives back what it was holding.
// The caller must hold bodySectionCacheMu.
func (s *IMAPSession) dropRetainedLocked() {
	data := s.bodySectionCacheData
	s.bodySectionCacheKey = ""
	s.bodySectionCacheData = nil

	if len(data) == 0 {
		return
	}
	s.server.reserveBodySectionCacheBytes(-int64(len(data)))
	if s.memTracker != nil {
		s.memTracker.Free(int64(len(data)))
	}
}

// memoryAvailable reports whether the session budget can take n more bytes, dropping the
// retained body section first if that is what stands in the way: bytes kept only to make
// the next chunk cheaper must never be the reason a fetch or an append is refused.
func (s *IMAPSession) memoryAvailable(n int64) bool {
	if s.memTracker == nil {
		return true
	}
	if s.memTracker.CanAllocate(n) {
		return true
	}
	s.releaseBodySectionCache()
	return s.memTracker.CanAllocate(n)
}

// reserveBodySectionCacheBytes accounts n bytes (negative to give them back) against the
// node-wide retention budget, reporting whether the reservation was granted.
func (s *IMAPServer) reserveBodySectionCacheBytes(n int64) bool {
	if s.bodySectionCacheBytes.Add(n) > maxServerBodySectionCacheBytes {
		s.bodySectionCacheBytes.Add(-n)
		return false
	}
	return true
}
