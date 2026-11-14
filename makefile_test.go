package sora

import (
	"bufio"
	"go/build/constraint"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// makeDryRun prints the commands `make target` would run (make -n), with env added to
// the environment.
func makeDryRun(t *testing.T, env []string, target string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not installed")
	}
	cmd := exec.Command("make", "-n", target)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", target, err, out)
	}
	return string(out)
}

// TestMakeResetTestDBResetsTheTestsDatabase: the test helpers use SORA_TEST_DB_NAME
// (integration_tests/common.SetupTestDatabase, db.setupTestDatabase), so the reset that
// runs before them has to reset that database, not drop the schema of sora_test_db under
// whoever else is testing against it. A reset that fails must stop make, not be ignored.
func TestMakeResetTestDBResetsTheTestsDatabase(t *testing.T) {
	out := makeDryRun(t, []string{"SORA_TEST_DB_NAME=sora_branch_example"}, "reset-test-db")
	if !strings.Contains(out, `SORA_TEST_DB_NAME="sora_branch_example"`) {
		t.Errorf("reset-test-db does not reset SORA_TEST_DB_NAME's database:\n%s", out)
	}
	if strings.Contains(out, "|| true") || strings.Contains(out, "/dev/null") {
		t.Errorf("reset-test-db hides a failed reset:\n%s", out)
	}
}

// integrationPackages returns the directories, relative to the module root, holding test
// files that build only with the integration tag.
func integrationPackages(t *testing.T) map[string]bool {
	t.Helper()
	pkgs := map[string]bool{}
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "package ") {
				break
			}
			if !constraint.IsGoBuild(line) {
				continue
			}
			expr, err := constraint.Parse(line)
			if err != nil {
				return err
			}
			with := expr.Eval(func(tag string) bool { return tag == "integration" })
			without := expr.Eval(func(string) bool { return false })
			if with && !without {
				pkgs[filepath.ToSlash(filepath.Dir(p))] = true
			}
			break
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("found no integration-tagged test files")
	}
	return pkgs
}

// packagesTestedWithIntegrationTag returns the package directories that the commands in
// a make -n listing run `go test -tags=integration` on, following `cd dir && go test .`.
func packagesTestedWithIntegrationTag(listing string) map[string]bool {
	pkgs := map[string]bool{}
	for _, line := range strings.Split(listing, "\n") {
		dir := "."
		for _, step := range strings.Split(line, "&&") {
			fields := strings.Fields(step)
			switch {
			case len(fields) == 2 && fields[0] == "cd":
				dir = fields[1]
			case len(fields) >= 2 && fields[0] == "go" && fields[1] == "test":
				tagged := false
				var args []string
				for _, f := range fields[2:] {
					if f == "-tags=integration" {
						tagged = true
					}
					if !strings.HasPrefix(f, "-") {
						args = append(args, f)
					}
				}
				if !tagged {
					continue
				}
				for _, a := range args {
					if a == "." || strings.HasPrefix(a, "./") {
						pkgs[path.Clean(path.Join(dir, a))] = true
					}
				}
			}
		}
	}
	return pkgs
}

// TestMakeIntegrationTestsRunsEveryIntegrationPackage: a package whose tests build only
// with the integration tag runs only when something passes -tags=integration for it. Each
// such package has to be in the aggregate targets, or nothing ever runs it.
func TestMakeIntegrationTestsRunsEveryIntegrationPackage(t *testing.T) {
	want := integrationPackages(t)
	for _, target := range []string{"integration-tests", "integration-tests-quick"} {
		got := packagesTestedWithIntegrationTag(makeDryRun(t, nil, target))
		for _, pkg := range slices.Sorted(maps.Keys(want)) {
			if target == "integration-tests-quick" && pkg == "integration_tests/imap_slowloris" {
				continue // quick mode leaves out the long-running timing tests on purpose
			}
			if !got[pkg] {
				t.Errorf("make %s does not run the integration tests in %s", target, pkg)
			}
		}
	}
}
