package delivery

import (
	"errors"
	"io"
	"testing"

	"github.com/emersion/go-message"
)

// An io.Reader may return data and an error together, and its later reads need
// not repeat that error. MultipartReader can recognize a prefetched close marker
// before consuming its buffered error, so the framing validator must retain it.
func TestVacationMIMEBoundaryReadErrorsFailClosed(t *testing.T) {
	for _, withData := range []bool{false, true} {
		name := "error before data"
		if withData {
			name = "error with final data"
		}
		t.Run(name, func(t *testing.T) {
			failure := errors.New("vacation MIME source read failed")
			var header message.Header
			header.Set("Content-Type", "multipart/mixed; boundary=b")
			header.Set("Content-Transfer-Encoding", "binary")
			body := &vacationMIMEOneShotReadError{err: failure}
			if withData {
				body.data = []byte("--b\r\n\r\nAway\r\n--b--\r\n")
			}
			err := validateVacationMIME(header, body, "text/plain", 0)
			if !errors.Is(err, failure) {
				t.Fatalf("validation error = %v, want source error %v", err, failure)
			}
		})
	}
}

type vacationMIMEOneShotReadError struct {
	data []byte
	err  error
	done bool
}

func (r *vacationMIMEOneShotReadError) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.done {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) != 0 {
		return n, nil
	}
	r.done = true
	return n, r.err
}
