package imap

import (
	"fmt"
	"io"
	"os"

	"github.com/migadu/go-imap"
)

// A session retains the last body section it fully extracted, or BINARY section it
// fully decoded, so that a client pulling one part in <offset.size> chunks does not
// reload the message and re-extract or re-decode the part for every chunk.
//
// Sections up to maxCachedBodySectionBytes stay in memory, bounded by:
//   - one section per session, dropped as soon as another section is retained, the
//     mailbox selection is cleared, or the client goes into IDLE;
//   - maxCachedBodySectionBytes per session and maxServerBodySectionCacheBytes node-wide;
//   - the session memory tracker, with memoryAvailable reclaiming an in-memory section
//     before refusing a later fetch or append.
//
// Sections above maxCachedBodySectionBytes up to maxSpilledBodySectionBytes (such as a
// 20 MB base64 attachment fetched in chunks, #1076) spill to an immediately-unlinked
// temporary file, bounded by maxServerSpilledBodySectionBytes across the node. A spilled
// section holds zero heap bytes in the session memory tracker between commands and serves
// subsequent <offset.size> slices via positional reads (ReadAt).
const (
	maxCachedBodySectionBytes        = 8 << 20
	maxServerBodySectionCacheBytes   = 256 << 20
	maxSpilledBodySectionBytes       = 128 << 20
	maxServerSpilledBodySectionBytes = 2 << 30
	maxCachedHeaderListBytes         = 1024
)

// bodySectionCacheKey identifies a body section independently of its <offset.size>
// slice, so successive chunk requests for the same section share one entry. The
// HEADER.FIELDS and HEADER.FIELDS.NOT names come off the wire as astrings and may hold a
// space, '|' or ']', so each name is quoted and each list labelled: no two different
// lists share a key. It returns an empty key, which disables the cache, for a message
// without a content hash, as without the hash there is nothing that ties the retained
// bytes to the message, and for header lists past maxCachedHeaderListBytes: each name
// may be a literal the command length limit does not count, and quoting writes a
// control byte as four.
func bodySectionCacheKey(contentHash string, section *imap.FetchItemBodySection) string {
	if contentHash == "" ||
		headerListBytes(section.HeaderFields)+headerListBytes(section.HeaderFieldsNot) > maxCachedHeaderListBytes {
		return ""
	}
	return fmt.Sprintf("%s|%s|%v|fields=%q|not=%q", contentHash, section.Specifier, section.Part,
		section.HeaderFields, section.HeaderFieldsNot)
}

// headerListBytes is the length of the names in a header list, counting a separator for
// each name so that a list of empty names is not free.
func headerListBytes(names []string) int {
	n := len(names)
	for _, name := range names {
		n += len(name)
	}
	return n
}

// binarySectionCacheKey identifies the decoded BINARY section of a part, which shares
// the one retained section with BODY: "BINARY" is no BODY section specifier, so the
// keys of the two never meet. Like bodySectionCacheKey it is empty without a content
// hash.
func binarySectionCacheKey(contentHash string, part []int) string {
	if contentHash == "" {
		return ""
	}
	return fmt.Sprintf("%s|BINARY|%v", contentHash, part)
}

// cachedBodySection returns the in-memory retained section for key, or nil.
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

// cachedSpilledSectionSize reports the byte length of a disk-spilled section retained
// under key, if present.
func (s *IMAPSession) cachedSpilledSectionSize(key string) (int, bool) {
	if key == "" {
		return 0, false
	}
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	if s.bodySectionCacheKey != key || s.bodySectionCacheFile == nil {
		return 0, false
	}
	return s.bodySectionCacheSize, true
}

// partialBounds computes [offset, offset+length) within a section of totalSize bytes,
// matching applyPartial's overflow-safe clamping.
func partialBounds(totalSize int, partial *imap.SectionPartial) (offset int64, length int) {
	if partial == nil {
		return 0, totalSize
	}
	if partial.Offset < 0 || partial.Offset >= int64(totalSize) || partial.Size <= 0 {
		return 0, 0
	}
	rem := int64(totalSize) - partial.Offset
	if partial.Size < rem {
		rem = partial.Size
	}
	return partial.Offset, int(rem)
}

// readSpilledSectionInto reads [offset, offset+len(dst)) from the spilled section for
// key using ReadAt so no file offset state is mutated.
func (s *IMAPSession) readSpilledSectionInto(key string, offset int64, dst []byte) bool {
	if len(dst) == 0 {
		return true
	}
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	if s.bodySectionCacheKey != key || s.bodySectionCacheFile == nil {
		return false
	}
	if offset < 0 || offset+int64(len(dst)) > int64(s.bodySectionCacheSize) {
		return false
	}
	_, err := io.ReadFull(io.NewSectionReader(s.bodySectionCacheFile, offset, int64(len(dst))), dst)
	return err == nil
}

// retainBodySection keeps data in memory as this session's single cached section. When it
// reports true it has taken over the caller's memory-tracker charge for data, which
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

// spillBodySection writes a section larger than maxCachedBodySectionBytes to an
// unlinked temporary file as this session's single retained section, holding zero
// heap bytes between commands.
func (s *IMAPSession) spillBodySection(key string, data []byte) bool {
	if key == "" || len(data) <= maxCachedBodySectionBytes || len(data) > maxSpilledBodySectionBytes {
		return false
	}
	if !s.server.reserveSpilledBodySectionBytes(int64(len(data))) {
		return false
	}

	f, err := os.CreateTemp("", "sora-imap-section-*")
	if err != nil {
		s.server.reserveSpilledBodySectionBytes(-int64(len(data)))
		return false
	}
	// Unlink immediately so the inode cannot outlive the process or be opened by path.
	// Do not write message bytes if the filesystem cannot remove the name.
	if err := os.Remove(f.Name()); err != nil {
		_ = f.Close()
		s.server.reserveSpilledBodySectionBytes(-int64(len(data)))
		return false
	}

	if n, err := f.Write(data); err != nil || n != len(data) {
		_ = f.Close()
		s.server.reserveSpilledBodySectionBytes(-int64(len(data)))
		return false
	}

	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()

	s.dropRetainedLocked()
	s.bodySectionCacheKey = key
	s.bodySectionCacheFile = f
	s.bodySectionCacheSize = len(data)
	return true
}

// releaseBodySectionCache drops the retained section (in memory or spilled) and gives
// back its node-wide reservation and any session memory charge it carried.
func (s *IMAPSession) releaseBodySectionCache() {
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	s.dropRetainedLocked()
}

// releaseInMemoryBodySectionCache drops the retained section only when it holds heap
// bytes charged to s.memTracker; a disk-spilled section carries no heap charge.
func (s *IMAPSession) releaseInMemoryBodySectionCache() {
	s.bodySectionCacheMu.Lock()
	defer s.bodySectionCacheMu.Unlock()
	if len(s.bodySectionCacheData) > 0 {
		s.dropRetainedLocked()
	}
}

// dropRetainedLocked forgets the retained section and gives back what it was holding.
// The caller must hold bodySectionCacheMu.
func (s *IMAPSession) dropRetainedLocked() {
	data := s.bodySectionCacheData
	f := s.bodySectionCacheFile
	spilledSize := s.bodySectionCacheSize

	s.bodySectionCacheKey = ""
	s.bodySectionCacheData = nil
	s.bodySectionCacheFile = nil
	s.bodySectionCacheSize = 0

	if len(data) > 0 {
		s.server.reserveBodySectionCacheBytes(-int64(len(data)))
		if s.memTracker != nil {
			s.memTracker.Free(int64(len(data)))
		}
	}
	if f != nil {
		_ = f.Close()
		s.server.reserveSpilledBodySectionBytes(-int64(spilledSize))
	}
}

// memoryAvailable reports whether the session budget can take n more bytes, dropping an
// in-memory retained body section first if that is what stands in the way: bytes kept
// only to make the next chunk cheaper must never be the reason a fetch or an append is
// refused.
func (s *IMAPSession) memoryAvailable(n int64) bool {
	if s.memTracker == nil {
		return true
	}
	if s.memTracker.CanAllocate(n) {
		return true
	}
	s.releaseInMemoryBodySectionCache()
	return s.memTracker.CanAllocate(n)
}

// reserveBodySectionCacheBytes accounts n bytes (negative to give them back) against the
// node-wide in-memory retention budget, reporting whether the reservation was granted.
func (s *IMAPServer) reserveBodySectionCacheBytes(n int64) bool {
	if s.bodySectionCacheBytes.Add(n) > maxServerBodySectionCacheBytes {
		s.bodySectionCacheBytes.Add(-n)
		return false
	}
	return true
}

// reserveSpilledBodySectionBytes accounts n bytes (negative to give them back) against
// the node-wide spilled-file retention budget.
func (s *IMAPServer) reserveSpilledBodySectionBytes(n int64) bool {
	if s.spilledBodySectionBytes.Add(n) > maxServerSpilledBodySectionBytes {
		s.spilledBodySectionBytes.Add(-n)
		return false
	}
	return true
}
