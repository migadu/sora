package sieveengine

import (
	"testing"
	"time"
)

func TestSetScriptExecutionTimeout(t *testing.T) {
	orig := scriptExecutionTimeout
	t.Cleanup(func() { scriptExecutionTimeout = orig })

	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero leaves unchanged", 0, orig},
		{"negative leaves unchanged", -5 * time.Second, orig},
		{"in range applied", 500 * time.Millisecond, 500 * time.Millisecond},
		{"below floor clamps up", 50 * time.Millisecond, minScriptExecutionTimeout},
		{"above ceiling clamps down", 5 * time.Minute, maxScriptExecutionTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scriptExecutionTimeout = orig
			SetScriptExecutionTimeout(c.in)
			if scriptExecutionTimeout != c.want {
				t.Errorf("SetScriptExecutionTimeout(%v) -> %v, want %v", c.in, scriptExecutionTimeout, c.want)
			}
		})
	}
}
