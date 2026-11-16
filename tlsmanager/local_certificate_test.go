//go:build unix

package tlsmanager

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

func TestLocalCertificateProcess(t *testing.T) {
	mode := os.Getenv("SORA_LOCAL_CERT_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("SORA_LOCAL_CERT_PATH")
	switch mode {
	case "write":
		data, err := os.ReadFile(os.Getenv("SORA_LOCAL_CERT_INPUT"))
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteLocalCertificateFile(context.Background(), path, data, nil); err != nil {
			t.Fatal(err)
		}
	case "hold":
		if err := WithLocalCertificateEntry(context.Background(), path, func(*os.Root, string) error {
			fmt.Println("LOCAL-CERT-READY")
			_, err := io.Copy(io.Discard, os.Stdin)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown local helper mode")
	}
}
func localCertificateChild(t *testing.T, path, input, mode string, hold bool) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalCertificateProcess$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "SORA_LOCAL_CERT_MODE="+mode, "SORA_LOCAL_CERT_PATH="+path, "SORA_LOCAL_CERT_INPUT="+input)
	if !hold {
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("local cache writer failed: %v (%d output bytes)", err, len(out))
		}
		return func() {}
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = in.Close()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	ready := make(chan bool, 1)
	go func() {
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			if strings.TrimSpace(scan.Text()) == "LOCAL-CERT-READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case yes := <-ready:
		if !yes {
			stop()
			t.Fatalf("local lease helper exited (%d stderr bytes)", stderr.Len())
		}
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("local lease helper timeout")
	}
	return stop
}
func TestLocalLeaseCancellationHasNoLateWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.example.com")
	c := &localCertificateCache{dir: dir}
	if err := c.Put(context.Background(), "mail.example.com", []byte("old")); err != nil {
		t.Fatal(err)
	}
	stop := localCertificateChild(t, path, "", "hold", true)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := c.Put(ctx, "mail.example.com", []byte("canceled")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked writer ignored cancellation: %v", err)
	}
	stop()
	if err := c.Put(context.Background(), "mail.example.com", []byte("new")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	data, err := c.Get(context.Background(), "mail.example.com")
	if err != nil || string(data) != "new" {
		t.Fatalf("late canceled write: bytes=%d err=%v", len(data), err)
	}
}
func TestLocalCanceledPrepareKeepsLeaseUntilJoined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.example.com")
	if err := WriteLocalCertificateFile(context.Background(), path, []byte("old"), nil); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		done <- WriteLocalCertificateFile(ctx, path, []byte("canceled"), func(*os.File, os.FileInfo) error { close(entered); <-release; return nil })
	}()
	<-entered
	cancel()
	blocked, cancelBlocked := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err := WithLocalCertificateEntry(blocked, path, func(*os.Root, string) error { return nil })
	cancelBlocked()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled operation unlocked before its work joined: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled prepared write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prepared writer did not join")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old" {
		t.Fatalf("canceled prepare published: bytes=%d %v", len(data), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), localPrivatePrefix+"temp-") {
			t.Fatal("canceled write leaked a temporary file")
		}
	}
}
func TestExpiredSyncSnapshotPreservesCrossProcessRenewal(t *testing.T) {
	const name = "mail.example.com"
	ctx := context.Background()
	store := &stubS3{objects: make(map[string][]byte)}
	entered, release := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var passed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() && r.Method == http.MethodGet && r.URL.Path == "/certs/"+S3ObjectKey(name) && passed.CompareAndSwap(false, true) {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		store.ServeHTTP(w, r)
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	dir := t.TempDir()
	m, _ := newTestLetsEncryptManager(t, srv.URL, func(le *config.TLSLetsEncryptConfig) { le.FallbackDir = dir })
	fc := extractFallbackCache(m.autocertMgr.Cache)
	expired := certCacheEntry(t, name, 1, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err := fc.storeLocal(ctx, name, expired, publicationGeneration{Value: "legacy", Known: true}); err != nil {
		t.Fatal(err)
	}
	renewed := certificateTestValue(t, 3)
	input := filepath.Join(t.TempDir(), "new-cert")
	if err := os.WriteFile(input, renewed, 0600); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- m.syncCertificateFromS3(ctx, name) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not reach S3 after its expired local snapshot")
	}
	localCertificateChild(t, filepath.Join(dir, name), input, "write", false)
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not finish")
	}
	data, _, err := fc.localSnapshot(ctx, name)
	if err != nil || !bytes.Equal(data, renewed) {
		t.Fatalf("expired snapshot removed the other process's renewal: bytes=%d err=%v", len(data), err)
	}
}
func TestLocalLeaseExistingHardlinkIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mail.example.com")
	lock := filepath.Join(dir, localPrivatePrefix+"lock-"+localDataFingerprint([]byte(filepath.Base(path))))
	if err := os.Link(victim, lock); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithLocalCertificateEntry(context.Background(), path, func(*os.Root, string) error {
		after, err := os.Stat(victim)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(localChangeTime(before), localChangeTime(after)) || before.Mode() != after.Mode() {
			return errors.New("existing hard-linked inode was changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func localChangeTime(info os.FileInfo) any {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	for _, n := range []string{"Ctimespec", "Ctim", "Ctime"} {
		f := v.FieldByName(n)
		if f.IsValid() {
			return f.Interface()
		}
	}
	return nil
}
