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
// real one acts on (rc.subr(8), run_rc_command): it starts "$command $rc_flags
// $command_args" through su(1) when ${name}_user is set, and status, stop and reload find
// the process with check_pidfile "$pidfile" "${procname:-$command}" and signal that PID
// (reload with $sig_reload). It then runs the start precmd with install(1) stubbed.
const rcSubrStub = `
load_rc_config() { eval "$TEST_RC_CONF"; }
install() { echo "install=$*"; }
run_rc_command() {
	eval _user=\$${name}_user
	echo "command=$command"
	echo "command_args=$command_args"
	echo "pidfile=$pidfile"
	echo "procname=$procname"
	echo "name_user=$_user"
	echo "sig_reload=$sig_reload"
	if [ -n "$start_precmd" ]; then $start_precmd; fi
}
`

// runRCScript runs dist/sora.rc against rcSubrStub, with rcConf evaluated where the real
// script's load_rc_config reads /etc/rc.conf, and returns its report.
func runRCScript(t *testing.T, rcConf string) (vars map[string]string, installs []string) {
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
	cmd := exec.Command("sh", rc, "start")
	cmd.Env = append(os.Environ(), "TEST_RC_CONF="+rcConf)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh sora.rc start: %v\n%s", err, out)
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
// run_rc_command runs, or rc.subr would start daemon through su(1) as that user.
func TestRCScriptDetachesAndWritesPidfile(t *testing.T) {
	for _, tc := range []struct {
		rcConf, user string
	}{
		{"", "sora"},
		{"sora_user=mailer", "mailer"},
	} {
		t.Run("user="+tc.user, func(t *testing.T) {
			vars, installs := runRCScript(t, tc.rcConf)
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
			if vars["procname"] != "/usr/local/bin/sora" {
				t.Errorf("procname = %q: check_pidfile must match the sora process, not $command", vars["procname"])
			}
			if i := slices.Index(args, "/usr/local/bin/sora"); i < 0 || !slices.Contains(args[i:], "--config") {
				t.Errorf("command_args %q do not run /usr/local/bin/sora --config", vars["command_args"])
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
