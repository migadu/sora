package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// Dovecot's lz4 files are not in the LZ4 frame format: "there is no standard LZ4 header,
// so we've created our own" (src/lib-compression/compression.c). A file is the magic and
// the largest uncompressed chunk size (4 bytes, big-endian), then chunks, each a 4-byte
// big-endian length and an LZ4 block of that many bytes (src/lib-compression/iostream-lz4.h).
// Dovecot writes 64 KiB chunks.
const (
	dovecotLZ4Magic = "Dovecot-LZ4\x0d\x2a\x9b\xc5"
	// dovecotLZ4MaxChunk is ISTREAM_LZ4_CHUNK_SIZE: Dovecot refuses a chunk, or a largest
	// uncompressed chunk size, above it.
	dovecotLZ4MaxChunk = 1 << 20
)

// dovecotLZ4Reader decompresses a file Dovecot stored with lz4, checking it the way
// Dovecot's istream-lz4.c reads it. It is stricter in one place: a file that ends inside
// a chunk length is an error, where Dovecot ends the message there.
type dovecotLZ4Reader struct {
	r   io.Reader
	src []byte // the compressed chunk
	dst []byte // room for the largest uncompressed chunk the header allows
	out []byte // decompressed bytes not yet read
	err error
}

func newDovecotLZ4Reader(r io.Reader) (*dovecotLZ4Reader, error) {
	var hdr [len(dovecotLZ4Magic) + 4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("lz4: truncated header: %w", err)
	}
	if string(hdr[:len(dovecotLZ4Magic)]) != dovecotLZ4Magic {
		return nil, errors.New("lz4: wrong magic in header")
	}
	maxChunk := binary.BigEndian.Uint32(hdr[len(dovecotLZ4Magic):])
	if maxChunk == 0 || maxChunk > dovecotLZ4MaxChunk {
		return nil, fmt.Errorf("lz4: invalid max chunk size %d (max %d)", maxChunk, dovecotLZ4MaxChunk)
	}
	return &dovecotLZ4Reader{r: r, dst: make([]byte, maxChunk)}, nil
}

func (z *dovecotLZ4Reader) Read(p []byte) (int, error) {
	// A chunk may decompress to nothing: read on rather than return 0, nil.
	for len(z.out) == 0 {
		if z.err != nil {
			return 0, z.err
		}
		z.err = z.nextChunk()
	}
	n := copy(p, z.out)
	z.out = z.out[n:]
	return n, nil
}

// nextChunk decompresses the next chunk into z.out, or returns io.EOF where the file ends
// between chunks.
func (z *dovecotLZ4Reader) nextChunk() error {
	var length [4]byte
	if _, err := io.ReadFull(z.r, length[:]); err != nil {
		if err == io.EOF {
			return io.EOF
		}
		return fmt.Errorf("lz4: truncated chunk length: %w", err)
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > dovecotLZ4MaxChunk {
		return fmt.Errorf("lz4: invalid chunk size %d", size)
	}
	if cap(z.src) < int(size) {
		z.src = make([]byte, size)
	}
	src := z.src[:size]
	if _, err := io.ReadFull(z.r, src); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("lz4: truncated chunk: %w", err)
	}
	n, err := lz4.UncompressBlock(src, z.dst)
	if err != nil {
		return fmt.Errorf("corrupted lz4 chunk: %w", err)
	}
	z.out = z.dst[:n]
	return nil
}
