package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"runtime"
	"testing"
)

// Client-side encryption is AES-256-GCM with the layout `nonce(12) || GCM(plaintext||tag)`.
// A deployment already holds a large body of objects in that layout, so the wire format is
// frozen: any change here has to stay byte-compatible in both directions or previously
// stored mail becomes unreadable.
//
// legacyEncrypt and legacyDecrypt are the original implementations, kept verbatim as the
// reference the current code is checked against. They are the contract; the production
// functions are the thing under test.

func legacyEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func legacyDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

func testStorage(t *testing.T) *S3Storage {
	t.Helper()
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return &S3Storage{Encrypt: true, EncryptionKey: key}
}

// sizes spans the boundaries that in-place buffer reuse gets wrong: empty input, a single
// byte, and sizes either side of the 16-byte AES block and the 16-byte GCM tag.
var sizes = []int{0, 1, 15, 16, 17, 31, 32, 33, 1024, 65536, 1 << 20}

// TestDecryptReadsLegacyCiphertext is the one that protects data already in the bucket.
func TestDecryptReadsLegacyCiphertext(t *testing.T) {
	s := testStorage(t)

	for _, n := range sizes {
		plaintext := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := append([]byte(nil), plaintext...)

		stored, err := legacyEncrypt(s.EncryptionKey, plaintext)
		if err != nil {
			t.Fatalf("legacyEncrypt(%d): %v", n, err)
		}

		got, err := s.decryptData(stored)
		if err != nil {
			t.Fatalf("decryptData on a legacy object of %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("decryptData(legacy %d bytes) did not round-trip: objects already in the bucket "+
				"would be unreadable", n)
		}
	}
}

// TestLegacyDecryptReadsCurrentCiphertext covers the other direction: a rollback, or an
// older binary in a mixed-version fleet, must still be able to read what this code writes.
func TestLegacyDecryptReadsCurrentCiphertext(t *testing.T) {
	s := testStorage(t)

	for _, n := range sizes {
		plaintext := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := append([]byte(nil), plaintext...)

		stored, err := s.encryptData(plaintext)
		if err != nil {
			t.Fatalf("encryptData(%d): %v", n, err)
		}

		got, err := legacyDecrypt(s.EncryptionKey, stored)
		if err != nil {
			t.Fatalf("legacyDecrypt of current output at %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("an older binary could not read what this code writes at %d bytes", n)
		}
	}
}

// TestEncryptDoesNotCorruptItsInput guards the specific hazard of in-place sealing: the
// caller's slice must not be left holding ciphertext, or a retry would re-encrypt already
// encrypted bytes and the stored object would be garbage.
func TestEncryptDoesNotCorruptItsInput(t *testing.T) {
	s := testStorage(t)

	for _, n := range sizes {
		if n == 0 {
			continue
		}
		plaintext := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := append([]byte(nil), plaintext...)

		if _, err := s.encryptData(plaintext); err != nil {
			t.Fatalf("encryptData(%d): %v", n, err)
		}
		if !bytes.Equal(plaintext, want) {
			t.Fatalf("encryptData overwrote its caller's buffer at %d bytes; a PUT retry would "+
				"encrypt the ciphertext a second time", n)
		}
	}
}

// TestEncryptLayoutIsUnchanged pins the wire format itself, independently of the round-trip
// tests: nonce first, then ciphertext and tag, and exactly the expected length.
func TestEncryptLayoutIsUnchanged(t *testing.T) {
	s := testStorage(t)

	const n = 4096
	plaintext := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}

	stored, err := s.encryptData(plaintext)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	const nonceSize, tagSize = 12, 16
	if got, want := len(stored), nonceSize+n+tagSize; got != want {
		t.Errorf("stored length = %d, want %d (nonce %d + plaintext %d + tag %d)",
			got, want, nonceSize, n, tagSize)
	}

	// The nonce must be the first 12 bytes: decrypting with it, by hand, must work.
	block, err := aes.NewCipher(s.EncryptionKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	got, err := gcm.Open(nil, stored[:nonceSize], stored[nonceSize:], nil)
	if err != nil {
		t.Fatalf("the first %d bytes are not the nonce: %v", nonceSize, err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("hand-decrypted payload does not match the plaintext")
	}
}

// measureAlloc reports bytes allocated while fn runs.
func measureAlloc(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestEncryptFromAllocatesOneBuffer is the reason for the change, measured on the path Put
// actually takes: reading the body AND encrypting it.
//
// The shape it replaces cost ~3x the message size - io.ReadAll grows by doubling, then
// Seal allocated the ciphertext separately - so plaintext and ciphertext were resident
// together. At the uploader's default concurrency of 20 that dominated the footprint and
// cancelled out streaming the body from disk. Measuring encryptData alone would prove
// nothing here, because its plaintext is allocated by the caller before the measurement.
func TestEncryptFromAllocatesOneBuffer(t *testing.T) {
	s := testStorage(t)

	const n = 8 << 20 // 8 MiB
	plaintext := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// The shape being replaced, measured here so the limit below is anchored to a real
	// number rather than a guess.
	oldPath := measureAlloc(func() {
		data, err := io.ReadAll(bytes.NewReader(plaintext))
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		out, err := s.encryptData(data)
		if err != nil {
			t.Fatalf("encryptData: %v", err)
		}
		runtime.KeepAlive(out)
	})

	var stored []byte
	newPath := measureAlloc(func() {
		var err error
		stored, err = s.encryptFrom(bytes.NewReader(plaintext), n)
		if err != nil {
			t.Fatalf("encryptFrom: %v", err)
		}
	})
	runtime.KeepAlive(stored)

	t.Logf("read+encrypt of %d bytes: old path %.2fx, encryptFrom %.2fx",
		n, float64(oldPath)/n, float64(newPath)/n)

	// One buffer is n+28 bytes. Allow headroom for allocator slack but stay far below the
	// two-buffer shape, so this asserts the shape and not the arithmetic.
	if limit := uint64(n) * 5 / 4; newPath > limit {
		t.Errorf("encryptFrom allocated %d bytes for a %d byte message (limit %d): the plaintext "+
			"and the ciphertext are both resident", newPath, n, limit)
	}
	if newPath >= oldPath {
		t.Errorf("encryptFrom allocated %d bytes, no better than the %d of the path it replaces",
			newPath, oldPath)
	}
}

// TestDecryptAllocatesOneBuffer is the same property on the read path, where Get holds the
// ciphertext and decryptData used to allocate a second buffer for the plaintext.
func TestDecryptAllocatesOneBuffer(t *testing.T) {
	s := testStorage(t)

	const n = 8 << 20
	plaintext := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}
	stored, err := s.encryptData(plaintext)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	var got []byte
	allocated := measureAlloc(func() {
		var err error
		got, err = s.decryptData(stored)
		if err != nil {
			t.Fatalf("decryptData: %v", err)
		}
	})
	runtime.KeepAlive(got)

	t.Logf("decrypt of %d bytes: %.2fx", n, float64(allocated)/n)
	// In place, so only the 12-byte nonce copy is allocated: an order of magnitude below n.
	if limit := uint64(n) / 4; allocated > limit {
		t.Errorf("decryptData allocated %d bytes for a %d byte message (limit %d): it is not "+
			"decrypting in place", allocated, n, limit)
	}
}

// TestEncryptFromMatchesEncryptData checks the one-allocation path against the original on
// every boundary size: same layout, same round-trip, readable by the legacy reader.
func TestEncryptFromMatchesEncryptData(t *testing.T) {
	s := testStorage(t)

	for _, n := range sizes {
		plaintext := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		want := append([]byte(nil), plaintext...)

		stored, err := s.encryptFrom(bytes.NewReader(plaintext), int64(n))
		if err != nil {
			t.Fatalf("encryptFrom(%d): %v", n, err)
		}
		if got, expect := len(stored), 12+n+16; got != expect {
			t.Errorf("encryptFrom(%d) produced %d bytes, want %d", n, got, expect)
		}

		got, err := legacyDecrypt(s.EncryptionKey, stored)
		if err != nil {
			t.Fatalf("legacyDecrypt of encryptFrom output at %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("encryptFrom output did not round-trip at %d bytes", n)
		}
		if !bytes.Equal(plaintext, want) {
			t.Fatalf("encryptFrom overwrote the source buffer at %d bytes", n)
		}
	}
}

// TestEncryptFromRejectsASizeMismatch covers the hazard of trusting the declared length: a
// body longer than its size would be silently truncated into the stored object, surfacing
// much later as a content-hash mismatch on read.
func TestEncryptFromRejectsASizeMismatch(t *testing.T) {
	s := testStorage(t)
	payload := []byte("the quick brown fox jumps over the lazy dog")

	if _, err := s.encryptFrom(bytes.NewReader(payload), int64(len(payload))-5); err == nil {
		t.Error("encryptFrom accepted a body longer than its declared size; the object would be truncated")
	}
	if _, err := s.encryptFrom(bytes.NewReader(payload), int64(len(payload))+5); err == nil {
		t.Error("encryptFrom accepted a body shorter than its declared size")
	}
}

// TestEncryptFromWithUnknownSize keeps the fallback working for a caller that cannot say
// how long the body is.
func TestEncryptFromWithUnknownSize(t *testing.T) {
	s := testStorage(t)
	payload := []byte("body of unknown length")

	stored, err := s.encryptFrom(bytes.NewReader(payload), -1)
	if err != nil {
		t.Fatalf("encryptFrom(-1): %v", err)
	}
	got, err := legacyDecrypt(s.EncryptionKey, stored)
	if err != nil {
		t.Fatalf("legacyDecrypt: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("unknown-size fallback did not round-trip")
	}
}

// TestDecryptRejectsTamperedCiphertext keeps the authentication guarantee explicit: reusing
// buffers must not turn into returning unverified plaintext.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	s := testStorage(t)

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	stored, err := s.encryptData(plaintext)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mangle func([]byte) []byte
	}{
		{"flipped byte in the body", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)/2] ^= 0x01
			return out
		}},
		{"flipped byte in the nonce", func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] ^= 0x01
			return out
		}},
		{"truncated tag", func(b []byte) []byte { return append([]byte(nil), b[:len(b)-1]...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.decryptData(tc.mangle(stored)); err == nil {
				t.Error("decryptData accepted tampered ciphertext")
			}
		})
	}
}
