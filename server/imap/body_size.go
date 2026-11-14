package imap

import "os"

// bodySizeMatches reports whether bytes read from a local copy of a message body (the
// staging spool or the cache) are the whole message. The row's size is the number of
// bytes that were stored; a local file that disagrees is a leftover of an interrupted
// write and must be treated as a miss, never served: S3 is the authority. A row with
// no recorded size only rules out an empty file.
func bodySizeMatches(data []byte, size int) bool {
	return bodyLenMatches(int64(len(data)), size)
}

// bodyLenMatches is bodySizeMatches for a local copy known only by its length, such
// as a file that is about to be streamed.
func bodyLenMatches(n int64, size int) bool {
	if size <= 0 {
		return n > 0
	}
	return n == int64(size)
}

// openLocalBody opens the local copy of a message body at path (the staging spool or
// the cache) for streaming, or returns nil when there is no whole copy there.
func openLocalBody(path string, size int) *os.File {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !bodyLenMatches(fi.Size(), size) {
		f.Close()
		return nil
	}
	return f
}
