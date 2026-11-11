package helpers

import (
	"io"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

const (
	previewMaxHeaderBytes  = 64 << 10
	previewMaxHeaderFields = 256
)

func readPreviewEntity(r io.Reader) (*message.Entity, error) {
	// go-message's top-level header reader only limits wire bytes. Every tiny
	// field also retains a backing array and bookkeeping, so limit field count
	// before handing bytes to it. Child headers inherit the parser's allocation
	// budget, which includes the slack capacity of those backing arrays.
	raw := io.LimitReader(r, previewMaxInput)
	header := &previewHeaderReader{r: raw, inHeader: true}
	return message.ReadWithOptions(header, &message.ReadOptions{MaxHeaderBytes: previewMaxHeaderBytes})
}

type previewHeaderReader struct {
	r            io.Reader
	inHeader     bool
	headerBytes  int
	headerFields int
	lineBytes    int
	lastCR       bool
	err          error
}

func (r *previewHeaderReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	for i, b := range p[:n] {
		if !r.inHeader {
			break
		}
		r.headerBytes++
		if r.headerBytes > previewMaxHeaderBytes {
			r.err = textproto.ErrHeaderTooBig
			return i, r.err
		}
		if r.lineBytes == 0 && b != '\r' && b != '\n' && b != ' ' && b != '\t' {
			r.headerFields++
			if r.headerFields > previewMaxHeaderFields {
				r.err = textproto.ErrHeaderTooBig
				return i, r.err
			}
		}
		if b == '\n' {
			if r.lineBytes == 0 || (r.lineBytes == 1 && r.lastCR) {
				r.inHeader = false
			}
			r.lineBytes, r.lastCR = 0, false
		} else {
			r.lineBytes++
			r.lastCR = b == '\r'
		}
	}
	return n, err
}
