package relayqueue

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteDataAtomicSyncContract asserts - by reading the AST of queue.go - that
// writeDataAtomic fsyncs the temp file before the rename and fsyncs the parent
// directory after it, the same shape as UploadWorker.StoreLocally.
//
// This guards the contract, not the physics: a real durability test would need a
// fault-injecting block layer. Neither os.Exit nor SIGKILL drops the page cache, so
// no crash simulation available here can distinguish a synced write from an unsynced
// one. The enforceable statement is that the sync calls exist and are ordered
// correctly around the rename.
func TestWriteDataAtomicSyncContract(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "queue.go", nil, 0)
	if err != nil {
		t.Fatalf("Failed to parse queue.go: %v", err)
	}

	fn := findFuncDecl(file, "writeDataAtomic")
	if fn == nil {
		t.Fatal("writeDataAtomic not found in queue.go")
	}

	// The variable holding the *os.File returned by os.CreateTemp.
	tmpVar := ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 {
			return true
		}
		for _, rhs := range assign.Rhs {
			if call, ok := rhs.(*ast.CallExpr); ok && calleeName(call) == "os.CreateTemp" {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
					tmpVar = ident.Name
				}
			}
		}
		return true
	})
	if tmpVar == "" {
		t.Fatal("writeDataAtomic does not create a temp file via os.CreateTemp")
	}

	var tmpSyncPos, renamePos, dirSyncPos token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		switch {
		case name == "os.Rename":
			if !renamePos.IsValid() {
				renamePos = call.Pos()
			}
		case name == tmpVar+".Sync":
			if !tmpSyncPos.IsValid() {
				tmpSyncPos = call.Pos()
			}
		// A sync of something other than the temp file: the parent directory, either
		// through a helper or through a directory handle opened inline.
		case name == "syncDir" || strings.HasSuffix(name, ".Sync"):
			if !dirSyncPos.IsValid() {
				dirSyncPos = call.Pos()
			}
		}
		return true
	})

	if !renamePos.IsValid() {
		t.Fatal("writeDataAtomic does not rename the temp file into place")
	}

	if !tmpSyncPos.IsValid() {
		t.Errorf("writeDataAtomic never calls %s.Sync(): the rename can land a zero-length file after a power loss, and for a Sieve redirect without :copy the queue file is the only copy of the message", tmpVar)
	} else if tmpSyncPos > renamePos {
		t.Errorf("writeDataAtomic calls %s.Sync() at %s, after the rename at %s: the data must be on stable storage before the name becomes visible",
			tmpVar, fset.Position(tmpSyncPos), fset.Position(renamePos))
	}

	if !dirSyncPos.IsValid() {
		t.Error("writeDataAtomic never fsyncs the parent directory: the rename itself can be lost in a crash, leaving no queue entry for a message LMTP already answered 250 for")
	} else if dirSyncPos < renamePos {
		t.Errorf("writeDataAtomic fsyncs the parent directory at %s, before the rename at %s: the directory entry created by the rename would not be covered",
			fset.Position(dirSyncPos), fset.Position(renamePos))
	}
}

// TestEnqueueWritesBodyBeforeMetadata asserts the write ordering inside Enqueue.
// AcquireNext keys off the .json file, so metadata visibility must imply the body is
// already durable; the reverse order leaves an orphaned .json after a crash that
// AcquireNext re-reads and error-logs on every scan, forever.
func TestEnqueueWritesBodyBeforeMetadata(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	if err := queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Subject: Test\r\n\r\nbody")); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	id := singlePendingID(t, queue)
	msgInfo, err := os.Stat(filepath.Join(queue.pendingDir, id+".msg"))
	if err != nil {
		t.Fatalf("Failed to stat message body: %v", err)
	}
	jsonInfo, err := os.Stat(filepath.Join(queue.pendingDir, id+".json"))
	if err != nil {
		t.Fatalf("Failed to stat metadata: %v", err)
	}

	if msgInfo.ModTime().After(jsonInfo.ModTime()) {
		t.Errorf("Enqueue wrote metadata (%s) before the body (%s): a crash between the two writes leaves a pending .json with no message to deliver",
			jsonInfo.ModTime().Format(time.RFC3339Nano), msgInfo.ModTime().Format(time.RFC3339Nano))
	}
}

// TestPeriodicCleanupReclaimsPendingOrphans drives the worker's periodic cleanup over
// a pending directory holding crash debris: metadata whose body never made it to disk
// (the pre-fix write order), a body whose metadata never made it (the post-fix write
// order), and a temp file from an interrupted atomic write. All three must be
// reclaimed, recent debris must be left alone, and a healthy message queued alongside
// them must still be delivered.
func TestPeriodicCleanupReclaimsPendingOrphans(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	stale := time.Now().Add(-24 * time.Hour)
	staleMetadata := filepath.Join(queue.pendingDir, "stale-metadata.json")
	writeFileAt(t, staleMetadata, []byte(`{"id":"stale-metadata","from":"sender@example.com","to":"recipient@example.com","type":"redirect","queued_at":"2020-01-01T00:00:00Z","attempts":0,"next_retry":"2020-01-01T00:00:00Z","errors":[]}`), stale)
	staleBody := filepath.Join(queue.pendingDir, "stale-body.msg")
	writeFileAt(t, staleBody, []byte("Subject: Orphan\r\n\r\nno metadata"), stale)
	staleTemp := filepath.Join(queue.pendingDir, ".tmp-999999999")
	writeFileAt(t, staleTemp, []byte("partial write"), stale)

	// Debris young enough to be a write still in flight must be preserved.
	freshBody := filepath.Join(queue.pendingDir, "fresh-body.msg")
	writeFileAt(t, freshBody, []byte("Subject: Fresh\r\n\r\nno metadata yet"), time.Now())
	freshTemp := filepath.Join(queue.pendingDir, ".tmp-111111111")
	writeFileAt(t, freshTemp, []byte("in flight"), time.Now())

	if err := queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Subject: Healthy\r\n\r\ndeliver me")); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 50*time.Millisecond, 10, 1, 50*time.Millisecond, time.Hour, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := worker.Start(ctx); err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !fileExists(staleMetadata) && !fileExists(staleBody) && !fileExists(staleTemp) && handler.getMessageCount() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if fileExists(staleMetadata) {
		t.Error("Periodic cleanup left an orphaned pending .json on disk: AcquireNext re-reads it and error-logs on every scan, forever")
	}
	if fileExists(staleBody) {
		t.Error("Periodic cleanup left an orphaned pending .msg on disk: nothing will ever reference it")
	}
	if fileExists(staleTemp) {
		t.Error("Periodic cleanup left a stale temp file on disk: interrupted atomic writes accumulate with no cleanup path")
	}
	if !fileExists(freshBody) {
		t.Error("Periodic cleanup removed a recently written .msg: it may be the body half of an enqueue still in flight")
	}
	if !fileExists(freshTemp) {
		t.Error("Periodic cleanup removed a recently created temp file: it may be an atomic write still in flight")
	}
	if got := handler.getMessageCount(); got != 1 {
		t.Errorf("Expected the healthy message to be delivered exactly once, got %d deliveries", got)
	}
}

// TestAcquireNextToleratesOrphanedMetadata verifies that metadata with no body does
// not block delivery of the healthy messages queued behind it.
func TestAcquireNextToleratesOrphanedMetadata(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Named to sort ahead of any UUID-based entry so AcquireNext hits it first.
	orphan := filepath.Join(queue.pendingDir, "0000-orphan.json")
	writeFileAt(t, orphan, []byte(`{"id":"0000-orphan","from":"sender@example.com","to":"recipient@example.com","type":"redirect","queued_at":"2020-01-01T00:00:00Z","attempts":0,"next_retry":"2020-01-01T00:00:00Z","errors":[]}`), time.Now())

	body := []byte("Subject: Healthy\r\n\r\ndeliver me")
	if err := queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", body); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	msg, msgBytes, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected the healthy message to be acquired despite the orphaned metadata")
	}
	if string(msgBytes) != string(body) {
		t.Errorf("Expected body %q, got %q", body, msgBytes)
	}
}

// findFuncDecl returns the named top-level function declaration, or nil.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// calleeName renders the callee of a call expression as "f", "pkg.F" or "recv.Method".
func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
		return "." + fun.Sel.Name
	}
	return ""
}

// writeFileAt writes a file and stamps it with the given modification time.
func writeFileAt(t *testing.T, path string, data []byte, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("Failed to write %s: %v", path, err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("Failed to set mtime on %s: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// singlePendingID returns the message ID of the only message in the pending directory.
func singlePendingID(t *testing.T, queue *DiskQueue) string {
	t.Helper()
	entries, err := os.ReadDir(queue.pendingDir)
	if err != nil {
		t.Fatalf("Failed to read pending directory: %v", err)
	}
	var ids []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	if len(ids) != 1 {
		t.Fatalf("Expected exactly 1 pending message, got %d", len(ids))
	}
	return ids[0]
}
