package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// waitForLog waits until logs holds want n times.
func waitForLog(t *testing.T, logs *syncLogBuffer, want string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(logs.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%q not logged %d times:\n%s", want, n, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SIGHUP's default action terminates the process, and sora took SIGHUP only once
// initializeServices had returned: after the migrations, the wait for other nodes'
// migrations, S3 and the cluster. A log rotation or a `systemctl reload` in that window
// killed it (#282). Now SIGHUP is taken from the start. During start-up it only reopens
// the log; the configuration reload needs the running servers, so it waits for them and
// runs once, however many SIGHUPs came.
func TestSIGHUPDuringStartUpWaitsForTheServers(t *testing.T) {
	logs := captureReloadLogs(t)
	h := listenForSIGHUP()
	t.Cleanup(func() { signal.Stop(h.signals) })

	const notice = "during start-up"
	for i := 1; i <= 2; i++ {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitForLog(t, logs, notice, i)
	}

	reloads := make(chan struct{}, 4)
	h.start(func() { reloads <- struct{}{} })
	select {
	case <-reloads:
	case <-time.After(5 * time.Second):
		t.Fatal("the reload asked for during start-up did not run once the servers started")
	}
	select {
	case <-reloads:
		t.Fatal("two SIGHUPs during start-up made more than one reload")
	case <-time.After(200 * time.Millisecond):
	}

	// Once the servers run, every SIGHUP reloads.
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloads:
	case <-time.After(5 * time.Second):
		t.Fatal("a SIGHUP after start did not reload")
	}
}

// Without a SIGHUP during start-up, starting does not reload.
func TestSIGHUPStartWithoutSignalDoesNotReload(t *testing.T) {
	h := listenForSIGHUP()
	t.Cleanup(func() { signal.Stop(h.signals) })

	reloads := make(chan struct{}, 1)
	h.start(func() { reloads <- struct{}{} })
	select {
	case <-reloads:
		t.Fatal("start reloaded without a SIGHUP")
	case <-time.After(200 * time.Millisecond):
	}
}

// main takes SIGHUP before any of its start-up work, so none of it runs with SIGHUP's
// default action.
func TestMainTakesSIGHUPBeforeStartUp(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(src), "\nfunc main() {")
	if start < 0 {
		t.Fatal("func main not found in main.go")
	}
	body := string(src[start:])
	hup := strings.Index(body, "listenForSIGHUP()")
	if hup < 0 {
		t.Fatal("main does not call listenForSIGHUP")
	}
	for _, work := range []string{"loadAndValidateConfig(", "logger.Initialize(", "initializeServices("} {
		i := strings.Index(body, work)
		if i < 0 {
			t.Errorf("main does not call %s; update this test", work)
		} else if i < hup {
			t.Errorf("main calls %s before it takes SIGHUP", work)
		}
	}
}
