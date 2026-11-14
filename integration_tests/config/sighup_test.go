//go:build integration

package config_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// lockedBuffer is a bytes.Buffer safe to read while the process writes it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// soraProcess is a running sora binary. err is set when exited is closed.
type soraProcess struct {
	cmd    *exec.Cmd
	out    *lockedBuffer
	exited chan struct{}
	err    error
}

func startSora(t *testing.T, cfgPath string) *soraProcess {
	t.Helper()
	p := &soraProcess{
		cmd:    exec.Command(common.GetSoraBinary(t), "-config", cfgPath),
		out:    &lockedBuffer{},
		exited: make(chan struct{}),
	}
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start sora: %v", err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exited:
		case <-time.After(15 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exited
		}
	})
	return p
}

// failIfKilledBySIGHUP fails the test if sora has exited, killed by SIGHUP.
func (p *soraProcess) failIfKilledBySIGHUP(t *testing.T) {
	t.Helper()
	select {
	case <-p.exited:
	default:
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(p.err, &exitErr) {
		return
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGHUP {
		t.Fatalf("sora was killed by SIGHUP (%v)\n--- output ---\n%s", p.err, p.out)
	}
}

// waitForFile waits until the file at path holds every one of want.
func waitForFile(t *testing.T, p *soraProcess, path string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		content, _ := os.ReadFile(path)
		missing := ""
		for _, w := range want {
			if !strings.Contains(string(content), w) {
				missing = w
				break
			}
		}
		if missing == "" {
			return
		}
		p.failIfKilledBySIGHUP(t)
		if time.Now().After(deadline) {
			t.Fatalf("%s does not hold %q\n--- %s ---\n%s\n--- output ---\n%s", path, missing, path, content, p.out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func writeConfigAtomically(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestSoraSurvivesSIGHUPDuringStartUp sends SIGHUP to sora while it is still in its
// start-up work, connecting to the database to run the migrations, after the log file was
// moved aside as newsyslog does. SIGHUP's default action terminates the process, and
// sora took SIGHUP only once that work was done, so a log rotation or a
// `systemctl reload` in the window killed it (#282). It must keep starting and write to
// a new log file at the configured path.
func TestSoraSurvivesSIGHUPDuringStartUp(t *testing.T) {
	// A database that accepts connections and never answers holds sora in start-up.
	db, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := db.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		db.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})

	dir := t.TempDir()
	logPath := filepath.Join(dir, "sora.log")
	cfgPath := filepath.Join(dir, "sora.toml")
	writeConfigAtomically(t, cfgPath, fmt.Sprintf(`
[logging]
output = %q
format = "console"
level = "info"

[database.write]
hosts = ["127.0.0.1"]
port = %d
user = "postgres"
name = "sora_sighup_test"

[[server]]
type = "http_admin_api"
name = "admin-api"
addr = %q
api_key = "sighup-test-key"
`, logPath, db.Addr().(*net.TCPAddr).Port, common.GetRandomAddress(t)))

	p := startSora(t, cfgPath)
	select {
	case <-accepted:
	case <-p.exited:
		t.Fatalf("sora exited before connecting to the database: %v\n--- output ---\n%s", p.err, p.out)
	case <-time.After(30 * time.Second):
		t.Fatalf("sora did not connect to the database within 30s\n--- output ---\n%s", p.out)
	}

	if err := os.Rename(logPath, logPath+".0"); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	waitForFile(t, p, logPath, "SIGHUP received during start-up")
	p.failIfKilledBySIGHUP(t)
}

// TestSoraReportsWhatASIGHUPDoesNotApply changes global settings and adds a [[server]]
// block on a running node, then sends SIGHUP. A reload applies none of them, and it used
// to say nothing about them either (#282): it must name each as needing a restart.
func TestSoraReportsWhatASIGHUPDoesNotApply(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sora.log")
	cfgPath := filepath.Join(dir, "sora.toml")
	metricsAddr := common.GetRandomAddress(t)
	base := fmt.Sprintf(`
[logging]
output = %q
format = "console"
level = "info"

[[server]]
type = "metrics"
name = "metrics"
addr = %q
`, logPath, metricsAddr)
	writeConfigAtomically(t, cfgPath, base)

	p := startSora(t, cfgPath)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if conn, err := net.DialTimeout("tcp", metricsAddr, 100*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		select {
		case <-p.exited:
			t.Fatalf("sora exited: %v\n--- output ---\n%s", p.err, p.out)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("sora did not start within 30s\n--- output ---\n%s", p.out)
		}
		time.Sleep(50 * time.Millisecond)
	}

	writeConfigAtomically(t, cfgPath, "bcrypt_cost = 13\n"+base+fmt.Sprintf(`
[uploader]
batch_size = 5

[[pool]]
name = "sora1"
backends = ["10.0.0.1:143"]
default = true

[[server]]
type = "metrics"
name = "metrics-2"
addr = %q
`, common.GetRandomAddress(t)))
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	waitForFile(t, p, logPath, "global settings changed but require restart", "bcrypt_cost", "uploader.batch_size", "pool", "server=metrics-2")
	content, _ := os.ReadFile(logPath)
	var restart, added bool
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "global settings changed but require restart") {
			restart = strings.Contains(line, "bcrypt_cost") && strings.Contains(line, "uploader.batch_size") && strings.Contains(line, "pool")
		}
		if strings.Contains(line, "server=metrics-2") && strings.Contains(line, "added") && strings.Contains(line, "restart") {
			added = true
		}
	}
	if !restart {
		t.Errorf("no restart notice naming bcrypt_cost, uploader.batch_size and pool\n--- log ---\n%s", content)
	}
	if !added {
		t.Errorf("no notice that the added metrics-2 server starts only on a restart\n--- log ---\n%s", content)
	}
}
