package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelpUsageLinesPassConfig (#2005): every Usage synopsis line, in the top-level help,
// each group overview and each subcommand's --help, shows --config the way the examples
// do (#1986), since every command but help and version needs it; and every subcommand's
// --help has an Examples section, so its Usage lines are not the only examples. The
// groups and subcommands are walked as in TestSubcommandHelpExamplesPassConfig.
func TestHelpUsageLinesPassConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkUsage := func(t *testing.T, out string) {
		t.Helper()
		lines := usageSection(out)
		if len(lines) == 0 {
			t.Fatalf("no Usage section:\n%s", out)
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "sora-admin ") {
				continue
			}
			if !passesConfigFlag(strings.Fields(line)) {
				t.Errorf("usage line omits --config: %s", line)
			}
		}
	}

	top, _ := runAdminMain(t, "--config", configPath, "help")
	t.Run("help", func(t *testing.T) { checkUsage(t, top) })
	groups := sectionFirstWords(top, "Commands")
	if len(groups) == 0 {
		t.Fatalf("no commands listed:\n%s", top)
	}
	walked := 0
	for _, group := range groups {
		if group == "help" || group == "version" {
			continue
		}
		overview, _ := runAdminMain(t, "--config", configPath, group, "help")
		t.Run(group, func(t *testing.T) { checkUsage(t, overview) })
		for _, sub := range groupSubcommands(group, overview) {
			walked++
			t.Run(group+" "+sub, func(t *testing.T) {
				t.Parallel()
				out, _ := runAdminMain(t, "--config", configPath, group, sub, "--help")
				checkUsage(t, out)
				if len(examplesSection(out)) == 0 {
					t.Errorf("no Examples section:\n%s", out)
				}
			})
		}
	}
	if walked < 50 {
		t.Fatalf("walked only %d subcommands; the overviews' format changed?", walked)
	}
}

// usageSection returns the lines of the "Usage:" section of a help text: the rest of the
// "Usage:" line and the indented lines after it, up to the first blank or unindented line.
func usageSection(text string) []string {
	_, rest, ok := strings.Cut(text, "Usage:")
	if !ok {
		return nil
	}
	first, rest, _ := strings.Cut(rest, "\n")
	var lines []string
	if strings.TrimSpace(first) != "" {
		lines = append(lines, first)
	}
	for _, line := range strings.Split(rest, "\n") {
		if strings.TrimSpace(line) == "" || (line[0] != ' ' && line[0] != '\t') {
			break
		}
		lines = append(lines, line)
	}
	return lines
}
