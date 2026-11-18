package lmtpproxy

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// expectGoroutinesExit fails the test if goroutines it started are still running once its
// cleanups have run: a fake backend that stays silent must end with the test (block on its
// connection or a channel the test closes), not park in a long sleep. Call it first, so its
// check runs after the test's other cleanups. Tests in this package do not run in parallel,
// so the goroutines that are new are the test's own.
func expectGoroutinesExit(t *testing.T) {
	t.Helper()
	before := map[string]bool{}
	for _, g := range goroutineStacks() {
		before[goroutineID(g)] = true
	}
	t.Cleanup(func() {
		var leaked []string
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			leaked = leaked[:0]
			for _, g := range goroutineStacks() {
				if !before[goroutineID(g)] {
					leaked = append(leaked, g)
				}
			}
			if len(leaked) == 0 || time.Now().After(deadline) {
				break
			}
		}
		if len(leaked) > 0 {
			t.Errorf("%d goroutines the test started still running 2s after it ended:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
		}
	})
}

func goroutineStacks() []string {
	buf := make([]byte, 1<<20)
	return strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n")
}

// goroutineID is the "goroutine N" prefix of a stack from runtime.Stack.
func goroutineID(stack string) string {
	id, _, _ := strings.Cut(stack, " [")
	return id
}
