package imap

// bodySizeMatches reports whether bytes read from a local copy of a message body (the
// staging spool or the cache) are the whole message. The row's size is the number of
// bytes that were stored; a local file that disagrees is a leftover of an interrupted
// write and must be treated as a miss, never served: S3 is the authority. A row with
// no recorded size only rules out an empty file.
func bodySizeMatches(data []byte, size int) bool {
	if size <= 0 {
		return len(data) > 0
	}
	return len(data) == size
}
