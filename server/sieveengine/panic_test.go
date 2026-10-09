package sieveengine

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/go-sieve/interp"
)

type panickingScript struct{}

func (panickingScript) Execute(context.Context, *interp.RuntimeData) error {
	panic("attempt to use an unusable variable: envelope.from")
}

// A panic in the interpreter becomes an evaluation error, which delivery
// handles by keeping the message, instead of unwinding into the LMTP
// connection (421, close, MTA retry into the same panic).
func TestRunScriptRecoversPanic(t *testing.T) {
	err := runScript(context.Background(), panickingScript{}, nil)
	if err == nil {
		t.Fatal("runScript returned nil for a panicking script")
	}
	if !strings.Contains(err.Error(), "sieve script panicked: attempt to use an unusable variable") {
		t.Fatalf("error = %q", err)
	}
	if !strings.Contains(err.Error(), "panic_test.go") {
		t.Fatalf("error carries no stack: %q", err)
	}
	if len(err.Error()) > maxPanicStackBytes+200 {
		t.Fatalf("error is %d bytes, stack not bounded", len(err.Error()))
	}
}

// With go-sieve refusing an unrequired namespace at load, the script that used
// to panic at delivery is now rejected on every write path by ValidateScript.
func TestValidateScriptRefusesUnrequiredNamespaceVariable(t *testing.T) {
	err := ValidateScript(`require ["fileinto", "variables"]; fileinto "${envelope.from}";`, nil)
	if err == nil || !strings.Contains(err.Error(), `${envelope.from} needs require "envelope"`) {
		t.Fatalf("ValidateScript = %v, want the envelope require error", err)
	}
	if err := ValidateScript(`require ["fileinto", "variables", "envelope"]; fileinto "${envelope.from}";`, nil); err != nil {
		t.Fatalf("with require envelope: %v", err)
	}
}
