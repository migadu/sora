package sieveengine

import (
	"strings"
	"testing"
)

// TestValidateScriptRefusesTestsuiteCommands is issue #1340: go-sieve loaded
// most vnd.dovecot.testsuite commands and tests without the require, so
// ManageSieve PUTSCRIPT, the User API and sora-admin stored them and delivery
// ran them. test_config_set "sieve_variables_max_variable_size" lifted the
// variable size limit of the compiled script, which SharedScriptCache shares
// between concurrent deliveries.
//
// RFC 5228 §2.10.5: "If an extension is not enabled with "require",
// implementations MUST treat it as if they did not support it at all." Sora
// never allows the require: go-sieve accepts it only in a Go test environment.
func TestValidateScriptRefusesTestsuiteCommands(t *testing.T) {
	refused := []struct {
		name   string
		script string
	}{
		{"test", `test "x" { stop; }`},
		{"test_set", `test_set "message" "Subject: x\r\n\r\nx\r\n";`},
		{"test_fail", `test_fail "x";`},
		{"test_binary_load", `test_binary_load "x";`},
		{"test_binary_save", `test_binary_save "x";`},
		{"test_config_reload", `test_config_reload;`},
		{"test_config_set", `test_config_set "sieve_variables_max_variable_size" "1000";`},
		{"test_config_unset", `test_config_unset "sieve_variables_max_variable_size";`},
		{"test_script_compile", `if test_script_compile "x" { stop; }`},
		{"test_script_run", `if test_script_run { stop; }`},
		{"test_error", `if test_error :contains "x" { stop; }`},
		{"require", `require "vnd.dovecot.testsuite";`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScript(tc.script, nil)
			if err == nil {
				t.Fatal("ValidateScript accepted the script")
			}
			if !strings.Contains(err.Error(), "vnd.dovecot.testsuite") {
				t.Fatalf("ValidateScript: %v, want an error naming vnd.dovecot.testsuite", err)
			}
		})
	}
}

// TestTestsuiteConfigSetCannotLiftVariableLimit is the reproducer from #1340:
// with test_config_set the script filed into "len-163840" instead of
// "len-4000". It must not compile, so delivery never runs it.
func TestTestsuiteConfigSetCannotLiftVariableLimit(t *testing.T) {
	script := `require ["variables", "fileinto"];
test_config_set "sieve_variables_max_variable_size" "100000000";
set "a" "0123456789012345678901234567890123456789";
` + strings.Repeat(`set "a" "${a}${a}";
`, 12) + `set :length "n" "${a}";
fileinto "len-${n}";
`
	if _, err := CompileScript(script, EffectiveExtensions(nil)); err == nil {
		t.Fatal("CompileScript accepted a script that raises sieve_variables_max_variable_size")
	}
}
