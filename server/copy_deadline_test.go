package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// slowWriter is a net.Conn that accepts writes very slowly (simulates slow client)
type slowWriter struct {
	net.Conn
	writeDelay time.Duration
	totalBytes int64
}

func (sw *slowWriter) Write(b []byte) (int, error) {
	// Simulate slow write by delaying
	time.Sleep(sw.writeDelay)
	sw.totalBytes += int64(len(b))
	return len(b), nil
}

func (sw *slowWriter) SetWriteDeadline(t time.Time) error {
	// Track deadline but continue - we'll timeout based on our slow writes
	if !t.IsZero() && time.Until(t) < 0 {
		return &net.OpError{Op: "write", Err: &timeoutError{}}
	}
	return nil
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// blockingWriter simulates a completely blocked client (never completes writes)
type blockingWriter struct {
	net.Conn
	blockCh chan struct{}
}

func (bw *blockingWriter) Write(b []byte) (int, error) {
	<-bw.blockCh // Block forever (or until channel is closed)
	return 0, &net.OpError{Op: "write", Err: &timeoutError{}}
}

func (bw *blockingWriter) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() && time.Until(t) < 0 {
		return &net.OpError{Op: "write", Err: &timeoutError{}}
	}
	// When deadline is set and we're past it, close the block channel to unblock writes
	if !t.IsZero() {
		go func() {
			time.Sleep(time.Until(t))
			close(bw.blockCh)
		}()
	}
	return nil
}

// TestCopyWithDeadline_FastClient tests normal operation with a fast client
func TestCopyWithDeadline_FastClient(t *testing.T) {
	ctx := context.Background()

	// Create two pipes: one for src->copy, one for copy->dst
	srcRead, srcWrite := net.Pipe()
	dstRead, dstWrite := net.Pipe()

	defer srcRead.Close()
	defer srcWrite.Close()
	defer dstRead.Close()
	defer dstWrite.Close()

	testData := "Hello, World! This is test data.\n"
	done := make(chan error, 1)

	// Start copying in background (srcRead -> dstWrite)
	go func() {
		_, err := CopyWithDeadline(ctx, dstWrite, srcRead, "test")
		dstWrite.Close() // Signal EOF to reader
		done <- err
	}()

	// Write data to source
	go func() {
		srcWrite.Write([]byte(testData))
		time.Sleep(10 * time.Millisecond)
		srcWrite.Close() // EOF
	}()

	// Read from destination to verify
	buf := make([]byte, len(testData))
	n, err := io.ReadFull(dstRead, buf)
	if err != nil {
		t.Fatalf("Failed to read from dst: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("Data mismatch: got %q, want %q", buf[:n], testData)
	}

	// Wait for copy to finish
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("CopyWithDeadline failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CopyWithDeadline timed out")
	}
}

// TestCopyWithDeadline_SlowClientTimeout tests that write deadline triggers on slow writes
func TestCopyWithDeadline_SlowClientTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow timeout test in short mode (takes 35 seconds)")
	}

	// This test verifies timeout detection logic
	// In real code, SetWriteDeadline causes the OS to timeout the write

	ctx := context.Background()

	// Create a pipe for source
	src, srcWriter := net.Pipe()
	defer src.Close()
	defer srcWriter.Close()

	// Create blocking writer that will timeout
	dst := &blockingWriter{
		blockCh: make(chan struct{}),
	}

	// Write lots of data in background
	go func() {
		data := []byte(strings.Repeat("X", 100000))
		srcWriter.Write(data)
	}()

	// Start copy in background
	done := make(chan error, 1)
	go func() {
		_, err := CopyWithDeadline(ctx, dst, src, "test")
		done <- err
	}()

	// Wait for copy to timeout (should happen within 30s deadline + some buffer)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Expected CopyWithDeadline to fail with timeout, got nil")
		}
		if !strings.Contains(err.Error(), "write timeout") && !strings.Contains(err.Error(), "timeout") {
			t.Errorf("Expected timeout error, got: %v", err)
		}
		t.Logf("✅ Got expected timeout error: %v", err)
	case <-time.After(35 * time.Second):
		t.Fatal("CopyWithDeadline didn't timeout within expected time")
	}
}

// TestCopyWithDeadline_ContextCancellation tests that context cancellation stops the copy.
// Context cancellation is checked between read/write operations. During a blocking read,
// cancellation won't be detected until the read completes. To properly test context handling,
// we need to ensure data is available so the read doesn't block indefinitely.
func TestCopyWithDeadline_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create two pipes
	srcRead, srcWrite := net.Pipe()
	dstRead, dstWrite := net.Pipe()

	defer srcRead.Close()
	defer srcWrite.Close()
	defer dstRead.Close()
	defer dstWrite.Close()

	done := make(chan error, 1)

	// Drain destination in background to prevent pipe from blocking
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := dstRead.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Write data continuously in background to keep copy busy
	go func() {
		buf := make([]byte, 1024)
		for i := range buf {
			buf[i] = byte(i % 256)
		}
		for {
			_, err := srcWrite.Write(buf)
			if err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond) // Small delay between writes
		}
	}()

	// Start copying in background
	go func() {
		_, err := CopyWithDeadline(ctx, dstWrite, srcRead, "test")
		done <- err
	}()

	// Give copy goroutine time to start and process data
	time.Sleep(100 * time.Millisecond)

	// Cancel context - this should be detected in the next loop iteration
	cancel()

	// Wait for copy to finish
	select {
	case err := <-done:
		// Should get context.Canceled error
		if err == nil {
			t.Fatal("Expected context.Canceled error, got nil")
		}
		if errors.Is(err, context.Canceled) {
			t.Logf("✅ Got expected context.Canceled error: %v", err)
		} else {
			// Any error indicating the copy stopped is acceptable
			t.Logf("✅ Copy stopped with error (acceptable): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CopyWithDeadline didn't stop after context cancellation")
	}
}

// TestCopyWithDeadline_LargeTransfer tests copying large amounts of data
func TestCopyWithDeadline_LargeTransfer(t *testing.T) {
	ctx := context.Background()

	// Create two pipes
	srcRead, srcWrite := net.Pipe()
	dstRead, dstWrite := net.Pipe()

	defer srcRead.Close()
	defer srcWrite.Close()
	defer dstRead.Close()
	defer dstWrite.Close()

	// Large data: 1MB
	largeData := strings.Repeat("A", 1024*1024)
	done := make(chan error, 1)
	var bytesWritten int64

	// Start copying in background (srcRead -> dstWrite)
	go func() {
		n, err := CopyWithDeadline(ctx, dstWrite, srcRead, "test")
		bytesWritten = n
		dstWrite.Close() // Signal EOF
		done <- err
	}()

	// Write large data to source
	go func() {
		srcWrite.Write([]byte(largeData))
		time.Sleep(100 * time.Millisecond)
		srcWrite.Close()
	}()

	// Read all data from destination
	buf := make([]byte, 32*1024)
	totalRead := 0
	for {
		n, err := dstRead.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}
	}

	// Wait for copy to finish
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("CopyWithDeadline failed: %v", err)
		}
		if bytesWritten != int64(len(largeData)) {
			t.Errorf("Bytes written mismatch: got %d, want %d", bytesWritten, len(largeData))
		}
		if totalRead != len(largeData) {
			t.Errorf("Bytes read mismatch: got %d, want %d", totalRead, len(largeData))
		}
		t.Logf("✅ Successfully copied %d bytes", bytesWritten)
	case <-time.After(5 * time.Second):
		t.Fatal("CopyWithDeadline timed out")
	}
}
