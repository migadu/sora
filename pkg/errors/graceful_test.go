package errors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// Once logging is initialized, a failure reported through the handler is an ERROR record
// of the configured logger, like every other error the process logs (#680). It was written
// to stderr instead, so with [logging] output = "syslog" the reason start-up stopped never
// reached syslog. The handler is made before logging is configured, as main makes it.
func TestErrorHandlerLogsThroughTheConfiguredLogger(t *testing.T) {
	tests := []struct {
		name   string
		report func(*ErrorHandler)
		want   map[string]string
	}{
		{
			name: "fatal error",
			report: func(eh *ErrorHandler) {
				eh.FatalError("initialize resilient database", fmt.Errorf("no healthy database pools available"))
			},
			want: map[string]string{"msg": "Fatal error", "operation": "initialize resilient database", "error": "no healthy database pools available"},
		},
		{
			name: "validation error",
			report: func(eh *ErrorHandler) {
				eh.ValidationError("S3 bucket", fmt.Errorf("missing required S3 bucket"))
			},
			want: map[string]string{"msg": "Invalid configuration", "field": "S3 bucket", "error": "missing required S3 bucket"},
		},
		{
			name: "configuration file error",
			report: func(eh *ErrorHandler) {
				eh.ConfigError("/etc/sora/config.toml", fmt.Errorf("toml: line 3: expected '='"))
			},
			want: map[string]string{"msg": "Failed to parse configuration file", "path": "/etc/sora/config.toml", "error": "toml: line 3: expected '='"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eh := NewErrorHandler()
			var buf bytes.Buffer
			prev := logger.Swap(slog.New(slog.NewJSONHandler(&buf, nil)))
			defer logger.Swap(prev)

			tt.report(eh)

			var rec map[string]any
			if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
				t.Fatalf("the configured logger has no record of the failure (%v): %q", err, buf.String())
			}
			if rec["level"] != "ERROR" {
				t.Errorf("level = %v, want ERROR", rec["level"])
			}
			for k, v := range tt.want {
				if rec[k] != v {
					t.Errorf("%s = %v, want %q", k, rec[k], v)
				}
			}
			if code := eh.WaitForExit(); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
		})
	}
}

// Before logging is configured its output is not known, so a failure is written to stderr,
// after what start-up held (logger.Hold), and in the words the start-up tests look for.
func TestErrorHandlerBeforeLoggingIsConfiguredWritesToStderr(t *testing.T) {
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	prevStderr, prevDefault, prev := os.Stderr, slog.Default(), logger.Swap(nil)
	os.Stderr = stderr
	defer func() {
		os.Stderr = prevStderr
		slog.SetDefault(prevDefault)
		logger.Swap(prev)
	}()

	eh := NewErrorHandler()
	logger.Hold()
	logger.Warn("Unknown configuration key", "key", "cleanup.grace_periood")
	eh.ValidationError("[relay]", fmt.Errorf(`unsupported [relay] type "SMTP"`))

	data, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	held := strings.Index(out, "cleanup.grace_periood")
	failure := strings.Index(out, `invalid configuration - [relay]: unsupported [relay] type "SMTP"`)
	if held < 0 || failure < 0 || held > failure {
		t.Errorf("stderr does not show the held warning and then the failure:\n%s", out)
	}
}

// With a file output and format = "json", the failure is a JSON record of that file, so the
// file stays one JSON record per line. It was written into it as a plain
// "[ERROR] ... FATAL: ..." line (#680).
func TestErrorHandlerKeepsAJSONLogFileJSON(t *testing.T) {
	eh := NewErrorHandler()
	path := filepath.Join(t.TempDir(), "sora.log")
	prevDefault := slog.Default()
	prev := logger.Swap(nil)
	lf, err := logger.Initialize(config.LoggingConfig{Output: path, Format: "json", Level: "error"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		lf.Close()
		logger.Swap(prev)
		slog.SetDefault(prevDefault)
	}()

	eh.FatalError("initialize timeout scheduler", fmt.Errorf("invalid shard count -2"))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("the JSON log file has a line that is not JSON (%v): %q", err, line)
			continue
		}
		if rec["level"] == "ERROR" && rec["operation"] == "initialize timeout scheduler" && rec["error"] == "invalid shard count -2" {
			found = true
		}
	}
	if !found {
		t.Errorf("the JSON log file has no ERROR record of the failure:\n%s", data)
	}
}
