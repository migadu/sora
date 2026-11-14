package dist

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rcSubrStub stands in for FreeBSD's /etc/rc.subr. Its run_rc_command reports what the
// real one acts on (rc.subr(8), run_rc_command): ${name}_program replaces $command; only
// the directives in $_keywords are accepted (reload only when $extra_commands lists it;
// anything else is "unknown directive" and exit 1); start runs "$command $rc_flags
// $command_args" through su(1) when ${name}_user is set; status, stop and reload find the
// process with check_pidfile "$pidfile" "${procname:-$command}" and signal that PID
// (reload with $sig_reload). It then runs the directive's precmd with install(1) stubbed.
const rcSubrStub = `
load_rc_config() { eval "$TEST_RC_CONF"; }
install() { echo "install=$*"; }
run_rc_command() {
	rc_arg=$1
	eval _override_command=\$${name}_program
	command=${_override_command:-$command}
	_keywords="start stop restart rcvar enable disable delete enabled describe extracommands $extra_commands"
	if [ -n "${procname:-$command}" ]; then _keywords="$_keywords status poll"; fi
	for _elem in $_keywords; do
		if [ "$_elem" != "$rc_arg" ]; then continue; fi
		eval _user=\$${name}_user _precmd=\$${rc_arg}_precmd
		echo "command=$command"
		echo "command_args=$command_args"
		echo "pidfile=$pidfile"
		echo "procname=$procname"
		echo "name_user=$_user"
		echo "sig_reload=$sig_reload"
		if [ -n "$_precmd" ]; then $_precmd; fi
		return 0
	done
	echo "$0: unknown directive '$rc_arg'." >&2
	exit 1
}
`

// runRCScript runs "dist/sora.rc rcArg" against rcSubrStub, with rcConf evaluated where the
// real script's load_rc_config reads /etc/rc.conf, and returns its report.
func runRCScript(t *testing.T, rcArg, rcConf string) (vars map[string]string, installs []string) {
	t.Helper()
	script, err := os.ReadFile("sora.rc")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "rc.subr")
	if err := os.WriteFile(stub, []byte(rcSubrStub), 0o644); err != nil {
		t.Fatal(err)
	}
	const source = ". /etc/rc.subr"
	if strings.Count(string(script), source) != 1 {
		t.Fatalf("sora.rc must source %q exactly once", source)
	}
	rc := filepath.Join(dir, "sora")
	if err := os.WriteFile(rc, []byte(strings.Replace(string(script), source, ". "+stub, 1)), 0o755); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("sh", "-n", rc).CombinedOutput(); err != nil {
		t.Fatalf("sh -n sora.rc: %v\n%s", err, out)
	}
	cmd := exec.Command("sh", rc, rcArg)
	cmd.Env = append(os.Environ(), "TEST_RC_CONF="+rcConf)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh sora.rc %s: %v\n%s", rcArg, err, out)
	}
	vars = map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "install" {
			installs = append(installs, v)
			continue
		}
		vars[k] = v
	}
	return vars, installs
}

// TestRCScriptDetachesAndWritesPidfile: sora stays in the foreground and writes no
// pidfile. Run directly, rc.subr waits on it (service sora start never returns), and
// status/stop/reload look for a pidfile that never appears. daemon(8) must detach it and
// write sora's PID to $pidfile, and since daemon changes the user itself (-u, which needs
// root to write the pidfile and to drop privileges), ${name}_user must not be set when
// run_rc_command runs, or rc.subr would start daemon through su(1) as that user. An rc.conf
// ${name}_program names the sora binary daemon runs; rc.subr must not run it in place of
// daemon.
func TestRCScriptDetachesAndWritesPidfile(t *testing.T) {
	for _, tc := range []struct {
		name, rcConf, user, program string
	}{
		{"default", "", "sora", "/usr/local/bin/sora"},
		{"sora_user", "sora_user=mailer", "mailer", "/usr/local/bin/sora"},
		{"sora_program", "sora_program=/opt/sora/bin/sora", "sora", "/opt/sora/bin/sora"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars, installs := runRCScript(t, "start", tc.rcConf)
			args := strings.Fields(vars["command_args"])
			flag := func(f string) string {
				if i := slices.Index(args, f); i >= 0 && i+1 < len(args) {
					return args[i+1]
				}
				return ""
			}

			if vars["command"] != "/usr/sbin/daemon" {
				t.Errorf("command = %q: sora does not detach, run it under /usr/sbin/daemon", vars["command"])
			}
			if vars["pidfile"] == "" || flag("-p") != vars["pidfile"] {
				t.Errorf("command_args %q do not write sora's PID (-p) to pidfile %q", vars["command_args"], vars["pidfile"])
			}
			if vars["procname"] != tc.program {
				t.Errorf("procname = %q, want %q: check_pidfile must match the sora process, not $command", vars["procname"], tc.program)
			}
			if i := slices.Index(args, tc.program); i < 0 || !slices.Contains(args[i:], "--config") {
				t.Errorf("command_args %q do not run %s --config", vars["command_args"], tc.program)
			}
			if flag("-u") != tc.user {
				t.Errorf("command_args %q: daemon -u = %q, want %q", vars["command_args"], flag("-u"), tc.user)
			}
			if vars["name_user"] != "" {
				t.Errorf("sora_user = %q at run_rc_command: rc.subr would run daemon(8) through su(1)", vars["name_user"])
			}
			if vars["sig_reload"] != "HUP" {
				t.Errorf("sig_reload = %q, want HUP", vars["sig_reload"])
			}
			if len(installs) == 0 {
				t.Error("start precmd created no directories")
			}
			for _, in := range installs {
				if !strings.Contains(in, "-o "+tc.user+" ") {
					t.Errorf("precmd %q does not give the directory to %s", in, tc.user)
				}
			}
		})
	}
}

// TestRCScriptOutputFileCanBeRotated: daemon(8) holds sora's stdout/stderr file (-o), which
// is where its logs go with the default [logging] output. newsyslog(8) can rotate it only by
// signalling daemon itself, which needs daemon's own PID in a supervisor pidfile (-P; the
// -p pidfile holds sora's), and daemon reopens the file on SIGHUP only with -H. Without
// both the file grows until sora is restarted.
func TestRCScriptOutputFileCanBeRotated(t *testing.T) {
	vars, _ := runRCScript(t, "start", "")
	args := strings.Fields(vars["command_args"])
	if i := slices.Index(args, vars["procname"]); i >= 0 {
		args = args[:i] // daemon's own options
	}
	flag := func(f string) string {
		if i := slices.Index(args, f); i >= 0 && i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	if flag("-o") == "" {
		t.Fatalf("command_args %q: daemon writes no output file (-o)", vars["command_args"])
	}
	if !slices.Contains(args, "-H") {
		t.Errorf("command_args %q: daemon does not reopen %s on SIGHUP (-H)", vars["command_args"], flag("-o"))
	}
	if p := flag("-P"); p == "" || p == vars["pidfile"] {
		t.Errorf("command_args %q: daemon -P = %q, want a supervisor pidfile other than %q", vars["command_args"], p, vars["pidfile"])
	}
}

// TestRCScriptReloadSignalsSora: rc.subr runs reload only when the script lists it in
// extra_commands ("Note that `reload' isn't provided by default, it should be enabled via
// $extra_commands"). Without it `service sora reload` fails with "unknown directive" and
// sora never gets the SIGHUP that reloads its configuration and reopens its log file.
func TestRCScriptReloadSignalsSora(t *testing.T) {
	vars, _ := runRCScript(t, "reload", "")
	if vars["sig_reload"] != "HUP" {
		t.Errorf("sig_reload = %q, want HUP", vars["sig_reload"])
	}
	if vars["procname"] != "/usr/local/bin/sora" {
		t.Errorf("procname = %q: reload must signal the sora process in %s", vars["procname"], vars["pidfile"])
	}
}
