package server

import (
	"errors"
	"fmt"
	"io"
)

// ErrMemoryBudgetExhausted marks a read or copy refused because the memory budget
// it is charged to cannot hold it. It is temporary: the budget frees as the work
// holding it ends.
var ErrMemoryBudgetExhausted = errors.New("memory budget exhausted")

// readAllChargedMinGrow is the first buffer ReadAllCharged allocates, and its
// smallest growth: most messages are smaller, so most reads allocate once.
const readAllChargedMinGrow = 32 << 10

// ReadAllCharged reads r to EOF into memory. Each time its buffer must grow, it
// first charges budget (nil: no budget) for the added capacity, so the budget
// holds at least the buffer's whole capacity before that capacity is allocated.
// A refused charge ends the read with an error wrapping ErrMemoryBudgetExhausted,
// without reading r any further.
//
// It returns the bytes read, the bytes charged and the first error. The caller
// frees what was charged (budget.Free) once it is done with the bytes, on every
// path, an error included.
func ReadAllCharged(r io.Reader, budget *SessionMemoryTracker) ([]byte, int64, error) {
	var buf []byte
	var charged int64
	for {
		if len(buf) == cap(buf) {
			grow := max(cap(buf), readAllChargedMinGrow)
			if budget != nil {
				if err := budget.Allocate(int64(grow)); err != nil {
					return buf, charged, fmt.Errorf("%w: %v", ErrMemoryBudgetExhausted, err)
				}
				charged += int64(grow)
			}
			next := make([]byte, len(buf), cap(buf)+grow)
			copy(next, buf)
			buf = next
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, charged, nil
		}
		if err != nil {
			return buf, charged, err
		}
	}
}

// ChargedReader charges Budget for every octet it reads from R, for a body that a
// decoder (JSON, multipart) buffers in its own way, so its buffer cannot be
// reserved ahead. Once a charge is refused, Read fails with an error wrapping
// ErrMemoryBudgetExhausted, and Refused reports it whatever the decoder makes of
// that error. The caller frees Charged once the decoded body is no longer needed.
type ChargedReader struct {
	R       io.Reader
	Budget  *SessionMemoryTracker
	Charged int64
	Refused bool
}

func (c *ChargedReader) Read(p []byte) (int, error) {
	if c.Refused {
		return 0, ErrMemoryBudgetExhausted
	}
	n, err := c.R.Read(p)
	if n > 0 && c.Budget != nil {
		if allocErr := c.Budget.Allocate(int64(n)); allocErr != nil {
			c.Refused = true
			return 0, fmt.Errorf("%w: %v", ErrMemoryBudgetExhausted, allocErr)
		}
		c.Charged += int64(n)
	}
	return n, err
}
