package server

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadAllCharged(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 10000) // 100000 bytes

	t.Run("no budget", func(t *testing.T) {
		got, charged, err := ReadAllCharged(bytes.NewReader(data), nil)
		if err != nil || !bytes.Equal(got, data) || charged != 0 {
			t.Fatalf("got %d bytes, charged %d, err %v", len(got), charged, err)
		}
	})

	t.Run("capacity charged before it is allocated", func(t *testing.T) {
		budget := NewSessionMemoryTracker(1 << 20)
		got, charged, err := ReadAllCharged(bytes.NewReader(data), budget)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("got %d bytes, err %v", len(got), err)
		}
		if charged != int64(cap(got)) || budget.Current() != charged {
			t.Fatalf("charged %d, budget holds %d, buffer capacity %d", charged, budget.Current(), cap(got))
		}
		budget.Free(charged)
		if budget.Current() != 0 {
			t.Fatalf("budget holds %d after the free", budget.Current())
		}
	})

	t.Run("refused growth stops the read", func(t *testing.T) {
		budget := NewSessionMemoryTracker(40 << 10)
		r := bytes.NewReader(data)
		got, charged, err := ReadAllCharged(r, budget)
		if !errors.Is(err, ErrMemoryBudgetExhausted) {
			t.Fatalf("err = %v, want ErrMemoryBudgetExhausted", err)
		}
		if int64(cap(got)) != charged || budget.Current() != charged || charged > 40<<10 {
			t.Fatalf("charged %d, budget holds %d, buffer capacity %d", charged, budget.Current(), cap(got))
		}
		if read := int64(len(data)) - int64(r.Len()); read > charged {
			t.Fatalf("read %d bytes past the %d charged", read, charged)
		}
	})
}

func TestChargedReader(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 10000)
	budget := NewSessionMemoryTracker(4000)
	c := &ChargedReader{R: bytes.NewReader(data), Budget: budget}
	_, err := io.ReadAll(c)
	if !errors.Is(err, ErrMemoryBudgetExhausted) || !c.Refused {
		t.Fatalf("err = %v, refused = %v; want the budget refusal", err, c.Refused)
	}
	if c.Charged > 4000 || budget.Current() != c.Charged {
		t.Fatalf("charged %d, budget holds %d", c.Charged, budget.Current())
	}
	if n, err := c.Read(make([]byte, 10)); n != 0 || !errors.Is(err, ErrMemoryBudgetExhausted) {
		t.Fatalf("read after the refusal: %d, %v", n, err)
	}

	ok := &ChargedReader{R: bytes.NewReader(data), Budget: NewSessionMemoryTracker(0)}
	if got, err := io.ReadAll(ok); err != nil || len(got) != len(data) || ok.Charged != int64(len(data)) {
		t.Fatalf("unlimited budget: %d bytes, charged %d, err %v", len(got), ok.Charged, err)
	}
}

// TestReadAllChargedGrowthKeepsOldBufferCharged: while the buffer grows, the old
// and the new backing arrays are both live during the copy, so the budget must
// hold both before the new one is allocated, and drop the old one only after the
// swap. A 40 KiB read under a 64 KiB budget ends in a 64 KiB buffer, which fits,
// but grows from 32 KiB to 64 KiB with 96 KiB live, which does not.
func TestReadAllChargedGrowthKeepsOldBufferCharged(t *testing.T) {
	t.Run("final capacity fits, old and new together do not", func(t *testing.T) {
		budget := NewSessionMemoryTracker(64 << 10)
		got, charged, err := ReadAllCharged(bytes.NewReader(bytes.Repeat([]byte("x"), 40<<10)), budget)
		if !errors.Is(err, ErrMemoryBudgetExhausted) {
			t.Fatalf("err = %v with %d bytes read into a %d-byte buffer; want the budget refusal at the 32 KiB -> 64 KiB growth", err, len(got), cap(got))
		}
		// The refusal leaves the old buffer, and only its charge, for the caller to free.
		if charged != 32<<10 || budget.Current() != charged || int64(cap(got)) != charged {
			t.Fatalf("after the refusal: charged %d, budget holds %d, buffer capacity %d; want 32 KiB each", charged, budget.Current(), cap(got))
		}
	})

	t.Run("peak charge covers old and new at every growth", func(t *testing.T) {
		budget := NewSessionMemoryTracker(1 << 20)
		got, charged, err := ReadAllCharged(bytes.NewReader(bytes.Repeat([]byte("x"), 100000)), budget)
		if err != nil {
			t.Fatal(err)
		}
		// Capacities 32 KiB, 64 KiB, 128 KiB: the last growth holds 64 + 128 KiB at once.
		if want := int64(64<<10 + 128<<10); budget.Peak() != want {
			t.Fatalf("peak charge %d, want %d (old and new buffer during the last copy)", budget.Peak(), want)
		}
		if charged != int64(cap(got)) || budget.Current() != charged {
			t.Fatalf("after the read: charged %d, budget holds %d, buffer capacity %d", charged, budget.Current(), cap(got))
		}
	})
}
