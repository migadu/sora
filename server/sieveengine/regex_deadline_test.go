package sieveengine

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestBodyRegexStopsAtScriptDeadline is issue #1545. A :regex match costs about
// the size of the key's program times the length of its input. The key below is
// some 10000 instructions, within go-sieve's program bound, and the body test
// feeds it up to 256 KB: the match takes 12-16 s of CPU. go-sieve stopped waiting
// for it at the script's deadline, but the match went on in a goroutine to the
// end, for every message delivered to the account. The deadline must stop the
// match itself.
func TestBodyRegexStopsAtScriptDeadline(t *testing.T) {
	orig := scriptExecutionTimeout
	t.Cleanup(func() { scriptExecutionTimeout = orig })
	SetScriptExecutionTimeout(200 * time.Millisecond)

	script := `require ["body", "regex", "fileinto"];
if body :raw :regex "` + strings.Repeat("a{999}", 10) + `b" { fileinto "m"; }
`
	executor, err := NewSieveExecutorWithExtensions(script, []string{"body", "regex", "fileinto"})
	if err != nil {
		t.Fatalf("create executor: %v", err)
	}

	start := time.Now()
	res, err := executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       map[string][]string{"Subject": {"hi"}},
		Message:      bodyOnly(strings.Repeat("a", 256*1024)),
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Evaluate = %+v, want the script to fail at its 200ms deadline", res)
	}
	if res.Action != ActionKeep {
		t.Errorf("action %q, want the implicit keep of a failed script", res.Action)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Evaluate returned after %v, want close to its 200ms deadline", elapsed)
	}

	for wait := time.Now().Add(500 * time.Millisecond); regexMatchRunning(); {
		if time.Now().After(wait) {
			t.Fatalf("a goroutine is still running the :regex match 500ms after Evaluate returned (%v)", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// regexMatchRunning reports whether a goroutine is running a regexp match.
func regexMatchRunning() bool {
	buf := make([]byte, 1<<20)
	return bytes.Contains(buf[:runtime.Stack(buf, true)], []byte(".(*Regexp).doExecute("))
}
