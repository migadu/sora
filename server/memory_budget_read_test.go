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
