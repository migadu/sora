package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// BenchmarkCopyWithDeadline benchmarks the optimized CopyWithDeadline function
func BenchmarkCopyWithDeadline(b *testing.B) {
	// Create a pipe for testing
	srcReader, srcWriter := net.Pipe()
	dstReader, dstWriter := net.Pipe()

	// Data to transfer (1 MB)
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Start goroutines to write/read data
		done := make(chan struct{})

		// Writer: sends testData to srcWriter
		go func() {
			srcWriter.Write(testData)
			srcWriter.Close()
		}()

		// Reader: reads from dstReader
		go func() {
			io.Copy(io.Discard, dstReader)
			close(done)
		}()

		// Copy with deadline
		ctx := context.Background()
		_, err := CopyWithDeadline(ctx, dstWriter, srcReader, "bench")
		if err != nil && err != io.EOF && err != io.ErrClosedPipe {
			b.Fatalf("CopyWithDeadline failed: %v", err)
		}

		dstWriter.Close()
		<-done

		// Reset connections for next iteration
		if i < b.N-1 {
			srcReader, srcWriter = net.Pipe()
			dstReader, dstWriter = net.Pipe()
		}
	}
}

// BenchmarkCopyWithDeadlineSmallChunks tests with many small writes
func BenchmarkCopyWithDeadlineSmallChunks(b *testing.B) {
	srcReader, srcWriter := net.Pipe()
	dstReader, dstWriter := net.Pipe()

	// Small chunk (1 KB)
	testData := make([]byte, 1024)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		done := make(chan struct{})

		go func() {
			// Write 100 small chunks
			for j := 0; j < 100; j++ {
				srcWriter.Write(testData)
			}
			srcWriter.Close()
		}()

		go func() {
			io.Copy(io.Discard, dstReader)
			close(done)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := CopyWithDeadline(ctx, dstWriter, srcReader, "bench")
		cancel()

		if err != nil && err != io.EOF && err != io.ErrClosedPipe {
			b.Fatalf("CopyWithDeadline failed: %v", err)
		}

		dstWriter.Close()
		<-done

		if i < b.N-1 {
			srcReader, srcWriter = net.Pipe()
			dstReader, dstWriter = net.Pipe()
		}
	}
}

// BenchmarkBufferPool benchmarks the buffer pool allocation overhead
func BenchmarkBufferPool(b *testing.B) {
	b.Run("PooledAllocation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bufp := copyBufPool.Get().(*[]byte)
			_ = *bufp
			copyBufPool.Put(bufp)
		}
	})

	b.Run("DirectAllocation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 32*1024)
			_ = buf
		}
	})
}
