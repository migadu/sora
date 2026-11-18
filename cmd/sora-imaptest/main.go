// sora-imaptest checks an existing IMAP endpoint using only the IMAP protocol.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/migadu/sora/internal/imaptest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	output := &checkedWriter{Writer: stdout}
	code := runCLI(ctx, args, output, stderr, lookupEnv)
	if output.err != nil {
		fmt.Fprintln(stderr, "write report:", output.err)
		return 2
	}
	return code
}

type checkedWriter struct {
	io.Writer
	err error
}

func (w *checkedWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.Writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	var cfg imaptest.Config
	var list bool
	var format, passwordEnv, passwordFile, rawlog, required string
	var timeout time.Duration
	flags := flag.NewFlagSet("sora-imaptest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.Addr, "addr", "", "running IMAP server address (host:port)")
	flags.StringVar(&cfg.Username, "user", "", "dedicated test account username")
	flags.StringVar(&passwordEnv, "password-env", "SORA_IMAPTEST_PASSWORD", "environment variable containing the password")
	flags.StringVar(&passwordFile, "password-file", "", "read password from a file instead of the environment (one trailing newline removed)")
	flags.StringVar(&cfg.TLSMode, "tls", "implicit", "transport: implicit, starttls, or none")
	flags.StringVar(&cfg.CAFile, "ca-file", "", "additional PEM certificate authorities")
	flags.StringVar(&cfg.ServerName, "server-name", "", "TLS server name (defaults to address host)")
	flags.BoolVar(&cfg.Insecure, "insecure", false, "disable TLS certificate verification for a test endpoint")
	flags.StringVar(&cfg.Run, "run", "", "regular expression selecting case names")
	flags.IntVar(&cfg.Clients, "clients", 1, "maximum concurrent independent test cases (each may use multiple connections)")
	flags.BoolVar(&list, "list", false, "list selected cases without connecting")
	flags.StringVar(&format, "format", "text", "report format: text or json")
	flags.StringVar(&required, "require-cap", "", "comma-separated capabilities that must be advertised after authentication")
	flags.DurationVar(&cfg.CommandTimeout, "command-timeout", 30*time.Second, "maximum duration of one command")
	flags.DurationVar(&cfg.CaseTimeout, "case-timeout", 2*time.Minute, "maximum duration of one case, excluding cleanup")
	flags.DurationVar(&cfg.FTSTimeout, "fts-timeout", 90*time.Second, "maximum wait for body indexing in nil and search-body cases")
	flags.DurationVar(&timeout, "timeout", 15*time.Minute, "maximum suite duration, excluding bounded cleanup")
	flags.StringVar(&rawlog, "rawlog", "", "write a protocol trace to a new file (authentication is redacted)")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sora-imaptest -addr host:port -user account [options]")
		fmt.Fprintln(stderr, "Runs IMAP protocol cases against an existing server using temporary mailboxes.")
		fmt.Fprintln(stderr, "The account must permit mailbox creation and message deletion.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments; use -help for usage")
		return 2
	}
	if format != "text" && format != "json" {
		fmt.Fprintln(stderr, "format must be text or json")
		return 2
	}
	if cfg.Clients < 1 || cfg.Clients > 1024 {
		fmt.Fprintln(stderr, "clients must be between 1 and 1024")
		return 2
	}
	cases, err := imaptest.Select(cfg.Run)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if list {
		if format == "json" {
			type listedCase struct {
				Name        string   `json:"name"`
				Description string   `json:"description"`
				RFC         string   `json:"rfc"`
				Requires    []string `json:"requires"`
				Upstream    string   `json:"upstream,omitempty"`
			}
			items := make([]listedCase, 0, len(cases))
			for _, c := range cases {
				requires := append([]string{}, c.Requires...)
				items = append(items, listedCase{c.Name, c.Description, c.RFC, requires, c.Upstream})
			}
			return writeJSON(stdout, stderr, items)
		}
		for _, c := range cases {
			fmt.Fprintf(stdout, "%s\n  %s\n  %s\n", c.Name, c.Description, c.RFC)
			if len(c.Requires) > 0 {
				fmt.Fprintf(stdout, "  Requires: %s\n", strings.Join(c.Requires, ", "))
			}
			if c.Upstream != "" {
				fmt.Fprintf(stdout, "  Upstream: %s\n", c.Upstream)
			}
		}
		return 0
	}
	if cfg.Addr == "" || cfg.Username == "" {
		fmt.Fprintln(stderr, "-addr and -user are required; -list needs neither")
		return 2
	}
	if timeout <= 0 || cfg.CommandTimeout <= 0 || cfg.CaseTimeout <= 0 || cfg.FTSTimeout <= 0 {
		fmt.Fprintln(stderr, "timeouts must be positive")
		return 2
	}
	if passwordFile != "" {
		file, err := os.Open(passwordFile)
		if err != nil {
			fmt.Fprintf(stderr, "open password file: %v\n", err)
			return 2
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 65537))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			fmt.Fprintln(stderr, "could not read password file")
			return 2
		}
		if len(data) > 65536 {
			fmt.Fprintln(stderr, "password file exceeds 64 KiB")
			return 2
		}
		cfg.Password = string(data)
		if trimmed, newline := strings.CutSuffix(cfg.Password, "\n"); newline {
			cfg.Password = strings.TrimSuffix(trimmed, "\r")
		}
	} else {
		var present bool
		cfg.Password, present = lookupEnv(passwordEnv)
		if !present {
			fmt.Fprintf(stderr, "password environment variable %q is not set; use -password-env or -password-file\n", passwordEnv)
			return 2
		}
	}
	cfg.RequiredCapabilities = strings.FieldsFunc(required, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if rawlog != "" {
		file, err := os.OpenFile(rawlog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintf(stderr, "create protocol trace: %v\n", err)
			return 2
		}
		defer file.Close()
		cfg.Trace = file
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var progress func(imaptest.Result)
	if format == "text" {
		progress = func(result imaptest.Result) {
			fmt.Fprintf(stdout, "[%s] %s (%s)\n", strings.ToUpper(result.Status), result.Name, result.Duration.Round(time.Millisecond))
			if result.Detail != "" {
				fmt.Fprintf(stdout, "  %s\n", result.Detail)
			}
			for _, detail := range result.CleanupErrors {
				fmt.Fprintf(stdout, "  cleanup: %s\n", detail)
			}
		}
	}
	report, _ := imaptest.Run(ctx, cfg, progress)
	if format == "json" {
		if code := writeJSON(stdout, stderr, report); code != 0 {
			return code
		}
	} else {
		if report.Error != "" {
			fmt.Fprintf(stdout, "ERROR: %s\n", report.Error)
		}
		fmt.Fprintf(stdout, "%d passed, %d failed, %d skipped, %d errors (%s)\n", report.Passed, report.Failed, report.Skipped, report.Errors, report.Duration.Round(time.Millisecond))
	}
	return report.ExitCode()
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(stderr, "write JSON report:", err)
		return 2
	}
	return 0
}
