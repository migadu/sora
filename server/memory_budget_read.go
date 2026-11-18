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

// ReadAllCharged reads r to EOF into memory. Its buffer starts at 32 KiB and
// doubles. Each time it must grow, the whole new capacity is charged to budget
// (nil: no budget) BEFORE it is allocated, while the old buffer is still charged:
// both are live during the copy. The old buffer's charge is dropped once the new
// one has replaced it, so after the read the charge is the buffer's capacity. A
// refused charge ends the read with an error wrapping ErrMemoryBudgetExhausted,
// without reading r any further; the old buffer and its charge are returned.
//
// It returns the bytes read, the bytes charged and the first error. The caller
// frees what was charged (budget.Free) once it is done with the bytes, on every
// path, an error included.
func ReadAllCharged(r io.Reader, budget *SessionMemoryTracker) ([]byte, int64, error) {
	var buf []byte
	var charged int64
	for {
		if len(buf) == cap(buf) {
			newCap := cap(buf) + max(cap(buf), readAllChargedMinGrow)
			if budget != nil {
				if err := budget.Allocate(int64(newCap)); err != nil {
					return buf, charged, fmt.Errorf("%w: %v", ErrMemoryBudgetExhausted, err)
				}
			}
			next := make([]byte, len(buf), newCap)
			copy(next, buf)
			buf = next
			if budget != nil {
				budget.Free(charged) // the old buffer is garbage now
				charged = int64(newCap)
			}
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

// Reserver returns a reserve callback (helpers.EncodeNULParts and the like) that
// charges t for the size it is passed and adds what it charged to *charged, which
// the caller frees once done with what was allocated. A refused charge is an
// error wrapping ErrMemoryBudgetExhausted. A nil t charges nothing.
func (t *SessionMemoryTracker) Reserver(charged *int64) func(size int64) error {
	return func(size int64) error {
		if t == nil {
			return nil
		}
		if err := t.Allocate(size); err != nil {
			return fmt.Errorf("%w: %v", ErrMemoryBudgetExhausted, err)
		}
		*charged += size
		return nil
	}
}
