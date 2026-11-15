package imap

import (
	"bytes"
	"context"
	"encoding/base64"
	"runtime"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
)

// base64AttachmentMessage builds a multipart/mixed message whose part 2 is
// payload under a base64 Content-Transfer-Encoding.
func base64AttachmentMessage(payload []byte) []byte {
	var b strings.Builder
	b.WriteString("From: sender@example.com\r\n")
	b.WriteString("To: rcpt@example.com\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n")
	b.WriteString("--BOUNDARY\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n")
	b.WriteString("--BOUNDARY\r\nContent-Type: application/octet-stream\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n--BOUNDARY--\r\n")
	return []byte(b.String())
}

// allocatedBy returns the heap bytes allocated while f ran.
func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A FETCH that names one part many times, as BINARY.PEEK[2]<offset.size> items
// or as BINARY.SIZE[2] next to BINARY[2], decodes the part once: a 50 KiB
// command line has room for some 2500 items, and each decode of a part is
// work, and memory, in the size of the part. The message has no content hash,
// so nothing a session retains between commands plays a part here.
func TestFetch_DecodeBinaryDecodesEachPartOnce(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 16*1024) // 256 KiB
	body := base64AttachmentMessage(payload)
	msg := fetchTestMessage(body)
	msg.ContentHash = ""

	decode := func(t *testing.T, options *imap.FetchOptions) (*decodedBinary, uint64) {
		t.Helper()
		s, _ := newFetchTestSession(0)
		bodyData, bodyFetched := body, true
		var b *decodedBinary
		var err error
		n := allocatedBy(func() {
			b, err = s.decodeBinary(context.Background(), &bodyData, &bodyFetched, options, msg)
		})
		if err != nil {
			t.Fatalf("decodeBinary: %v", err)
		}
		s.freeSectionCopies(b.charged)
		return b, n
	}

	t.Run("partials of one part", func(t *testing.T) {
		const chunk = 16
		chunks := func(n int) *imap.FetchOptions {
			options := &imap.FetchOptions{}
			for i := range n {
				options.BinarySection = append(options.BinarySection, &imap.FetchItemBinarySection{
					Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: int64(i) * 4096, Size: chunk},
				})
			}
			return options
		}
		_, one := decode(t, chunks(1))
		b, many := decode(t, chunks(64))
		for i, got := range b.sections {
			if want := payload[i*4096 : i*4096+chunk]; !bytes.Equal(got, want) {
				t.Fatalf("section %d = %q, want %q", i, got, want)
			}
		}
		if many > 4*one {
			t.Errorf("64 partials of part 2 allocated %d bytes, one partial %d: the part is decoded per item", many, one)
		}
	})

	t.Run("BINARY.SIZE next to BINARY", func(t *testing.T) {
		section := []*imap.FetchItemBinarySection{{Part: []int{2}, Peek: true}}
		_, alone := decode(t, &imap.FetchOptions{BinarySection: section})
		options := &imap.FetchOptions{BinarySection: section}
		for range 256 {
			options.BinarySectionSize = append(options.BinarySectionSize, &imap.FetchItemBinarySectionSize{Part: []int{2}})
		}
		b, withSizes := decode(t, options)
		if !bytes.Equal(b.sections[0], payload) {
			t.Fatalf("BINARY[2] = %d bytes, want the %d-byte payload", len(b.sections[0]), len(payload))
		}
		for i, n := range b.sizes {
			if n != uint32(len(payload)) {
				t.Fatalf("BINARY.SIZE[2] item %d = %d, want %d", i, n, len(payload))
			}
		}
		if withSizes > 2*alone {
			t.Errorf("BINARY[2] with 256 BINARY.SIZE[2] allocated %d bytes, BINARY[2] alone %d: the size is decoded again per item", withSizes, alone)
		}
	})
}

// A client that downloads a part in BINARY[n]<offset.size> chunks, one FETCH
// per chunk, has every chunk after the first answered from the section the
// session decoded for the first, as BODY[n]<offset.size> chunks are: the second
// command below cannot load the message body at all.
func TestFetch_BinaryChunksReuseDecodedSection(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4*1024) // 64 KiB
	body := base64AttachmentMessage(payload)
	msg := fetchTestMessage(body)
	const chunk = 16 * 1024

	s, tracker := newFetchTestSession(0)
	bodyData, bodyFetched := body, true
	first, err := s.decodeBinary(context.Background(), &bodyData, &bodyFetched, &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}}},
	}, msg)
	if err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if !bytes.Equal(first.sections[0], payload[:chunk]) {
		t.Fatalf("first chunk = %d bytes, want %d", len(first.sections[0]), chunk)
	}
	s.freeSectionCopies(first.charged)

	var noBody []byte
	noBodyFetched := true
	second, err := s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
		BinarySection:     []*imap.FetchItemBinarySection{{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: chunk, Size: chunk}}},
		BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}},
	}, msg)
	if err != nil {
		t.Fatalf("second chunk: %v", err)
	}
	if !bytes.Equal(second.sections[0], payload[chunk:2*chunk]) || second.sizes[0] != uint32(len(payload)) {
		t.Fatalf("second chunk = %d bytes (BINARY.SIZE %d), want %d (BINARY.SIZE %d): the decoded section was not retained",
			len(second.sections[0]), second.sizes[0], chunk, len(payload))
	}
	s.freeSectionCopies(second.charged)

	// The retained section is charged for as long as it is held, and given back
	// when the mailbox selection is dropped.
	if got, want := tracker.Current(), int64(len(payload)); got != want {
		t.Errorf("retained section charge = %d bytes, want %d", got, want)
	}

	// The retained BINARY[2] answers neither BINARY[1] nor BODY[2], whose bytes
	// differ from it.
	other, err := s.decodeBinary(context.Background(), &noBody, &noBodyFetched, &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{{Part: []int{1}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}}},
	}, msg)
	if err != nil || len(other.sections[0]) != 0 {
		t.Errorf("BINARY[1] without a body = %d bytes, %v; want an empty section", len(other.sections[0]), err)
	}
	w := &fakeBodySectionWriter{tracker: tracker}
	if err := s.handleBodySections(context.Background(), w, &noBody, &noBodyFetched, &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{Part: []int{2}, Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: chunk}}},
	}, msg); err != nil {
		t.Fatalf("BODY[2]: %v", err)
	}
	if len(w.sections) != 1 || len(w.sections[0].data) != 0 {
		t.Errorf("BODY[2] without a body was answered from the retained BINARY[2]")
	}

	s.mutex.Lock()
	s.clearSelectedMailboxStateLocked()
	s.mutex.Unlock()
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after clearing mailbox state = %d bytes, want 0", got)
	}
}
