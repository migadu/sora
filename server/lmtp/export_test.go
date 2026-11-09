//go:build integration

package lmtp

import "testing"

// SetDefaultSieveScriptForTest replaces the embedded script before New compiles it.
// Tests using it must not run in parallel with other LMTP constructors.
func SetDefaultSieveScriptForTest(t *testing.T, script string) {
	t.Helper()
	original := defaultSieveScript
	defaultSieveScript = script
	t.Cleanup(func() { defaultSieveScript = original })
}
