// Package logger provides structured logging for the Sora email server.
//
// This package wraps Go's standard library slog for high-performance
// structured logging with support for multiple outputs, chosen by
// config.LoggingConfig.Output:
//   - Console: "stderr" (the default) or "stdout"
//   - Syslog: "syslog", the local syslog daemon only
//   - File: any other value is the path of the log file (reopened on SIGHUP,
//     so newsyslog or logrotate can rotate it)
//
// # Initialization
//
// Initialize the logger once at application startup:
//
//	cfg := config.LoggingConfig{
//		Output: "/var/log/sora/sora.log",
//		Level:  "info",
//		Format: "json",
//	}
//	logFile, err := logger.Initialize(cfg)
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "initializing logger: %v\n", err)
//	}
//	if logFile != nil { // nil unless the output is a file
//		defer logFile.Close()
//	}
//
// # Usage
//
// Use the package-level functions for logging:
//
//	logger.Info("Server started successfully")
//	logger.InfoContext(ctx, "Listening on address", "addr", addr)
//	logger.Warn("High memory usage detected")
//	logger.Error("Failed to connect to database", "error", err)
//	logger.Fatal("Critical error, shutting down")
//
// # Structured Logging
//
// Use key-value pairs for structured fields:
//
//	logger.Info("Mailbox access",
//		"account_id", 123,
//		"mailbox", "INBOX",
//		"message_count", 42,
//	)
//
// # Log Levels
//
// Supported levels (in order of severity):
//   - debug: Detailed information for debugging
//   - info: General informational messages
//   - warn: Warning messages for potential issues
//   - error: Error messages for failures
//
// # Output Formats
//
// Two formats are supported:
//   - json: Machine-readable structured JSON
//   - console: Human-readable text output
//
// # Syslog Integration
//
// Output = "syslog" writes to the local syslog daemon with the fixed tag "sora"
// (facility daemon); Format does not apply. Remote syslog is not supported: have
// the local daemon forward to a remote collector. If the local daemon cannot be
// reached, or on Windows, the logger falls back to stderr.
//
//	cfg := config.LoggingConfig{
//		Output: "syslog",
//		Level:  "info",
//	}
//
// # Performance
//
// The logger uses Go's standard slog for high-performance structured logging
// with minimal allocations.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/migadu/sora/config"
)

// syslogLineSanitizer collapses CR/LF. Unlike Go's stdlib slog handlers (which
// escape control chars), the syslog writer emits the message verbatim, so an
// attacker-controlled field (username, mailbox name, …) could otherwise inject a
// forged syslog line. sanitizeSyslogLine is applied to every syslog message.
var syslogLineSanitizer = strings.NewReplacer("\n", "\\n", "\r", "\\r")

func sanitizeSyslogLine(s string) string {
	return syslogLineSanitizer.Replace(s)
}

// formatSyslogMessage renders a record for the syslog writer as
// "<message> key=value ...", handler attrs first, then the record's own.
// Values are rendered the way slog.TextHandler renders them, so the attribute
// part is valid logfmt and a parser (e.g. VictoriaLogs' unpack_logfmt) splits it
// into the right fields: error=connection refused would otherwise become
// error=connection plus a stray key "refused". CR/LF are collapsed afterwards to
// prevent log forging.
func formatSyslogMessage(r slog.Record, handlerAttrs []slog.Attr) string {
	var b strings.Builder
	b.WriteString(r.Message)
	writeAttr := func(a slog.Attr) {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(formatAttrValue(a.Value))
	}
	for _, a := range handlerAttrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	return sanitizeSyslogLine(b.String())
}

// formatAttrValue returns the value bare when it is a single logfmt token, and
// quoted (strconv.Quote) when it is empty or contains whitespace, '=', '"' or a
// non-printable character, matching slog.TextHandler.
func formatAttrValue(v slog.Value) string {
	s := v.Resolve().String()
	if needsQuoting(s) {
		return strconv.Quote(s)
	}
	return s
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r == '=' || r == '"' || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// globalLogger is the logger every package-level function logs through. It is atomic
// because tests re-Initialize or Swap it while servers from earlier tests still log.
var globalLogger atomic.Pointer[slog.Logger]

// fileOutput is the file output, when the configured output is a path; nil
// otherwise. Retained output writers load it on every write, including writers
// created before Initialize.
var fileOutput atomic.Pointer[LogFile]

// Stdout returns a writer for unstructured output such as protocol debug logs.
// It follows the configured log file across rotations, or writes to os.Stdout
// when file logging is not configured. The writer may be kept across Initialize.
func Stdout() io.Writer { return streamWriter{} }

// Stderr is like Stdout, but falls back to os.Stderr. It can be used by error
// handlers created before logging is initialized.
func Stderr() io.Writer { return streamWriter{stderr: true} }

type streamWriter struct{ stderr bool }

func (w streamWriter) Write(p []byte) (int, error) {
	if lf := fileOutput.Load(); lf != nil {
		return lf.Write(p)
	}
	if w.stderr {
		return os.Stderr.Write(p)
	}
	return os.Stdout.Write(p)
}

// LogFile is a log output that can be reopened under the running handler.
// newsyslog renames the file and then signals the process; writing on
// through the old descriptor would fill the rotated file, which is then
// compressed and lost.
type LogFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openLogFile(path string) (*LogFile, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &LogFile{path: path, f: f}, nil
}

// Name returns the path of the log file.
func (lf *LogFile) Name() string { return lf.path }

func (lf *LogFile) Write(p []byte) (int, error) {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.f == nil {
		return 0, os.ErrClosed
	}
	return lf.f.Write(p)
}

// Close closes the current descriptor.
func (lf *LogFile) Close() error {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.f == nil {
		return os.ErrClosed
	}
	err := lf.f.Close()
	lf.f = nil
	fileOutput.CompareAndSwap(lf, nil)
	return err
}

// reopen swaps the underlying file while holding the same lock as every writer.
// Saved Stdout and Stderr writers go through this handle too, so rotation never
// closes a descriptor beneath an in-flight write. If opening fails, the old
// file remains usable.
func (lf *LogFile) reopen() error {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.f == nil {
		return fmt.Errorf("reopen log file %s: %w", lf.path, os.ErrClosed)
	}
	f, err := os.OpenFile(lf.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("reopen log file %s: %w", lf.path, err)
	}
	old := lf.f
	lf.f = f
	if err := old.Close(); err != nil {
		return fmt.Errorf("close rotated log file %s: %w", lf.path, err)
	}
	return nil
}

// Reopen reopens the log file after a rotation tool such as newsyslog has moved
// it aside; main calls it on SIGHUP. A no-op when the output is not a file.
func Reopen() error {
	lf := fileOutput.Load()
	if lf == nil {
		return nil
	}
	return lf.reopen()
}

// syslogHandler wraps syslog.Writer to implement slog.Handler
type syslogHandler struct {
	writer *syslog.Writer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func newSyslogHandler(w *syslog.Writer, level slog.Level) *syslogHandler {
	return &syslogHandler{
		writer: w,
		level:  level,
		attrs:  []slog.Attr{},
		groups: []string{},
	}
}

func (h *syslogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *syslogHandler) Handle(_ context.Context, r slog.Record) error {
	msg := formatSyslogMessage(r, h.attrs)

	switch r.Level {
	case slog.LevelDebug:
		return h.writer.Debug(msg)
	case slog.LevelInfo:
		return h.writer.Info(msg)
	case slog.LevelWarn:
		return h.writer.Warning(msg)
	case slog.LevelError:
		return h.writer.Err(msg)
	default:
		return h.writer.Info(msg)
	}
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &syslogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name
	return &syslogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  h.attrs,
		groups: newGroups,
	}
}

// Initialize sets up the global logger based on configuration. With a file
// path as output it returns the file, which Reopen swaps on SIGHUP; nil
// otherwise.
func Initialize(cfg config.LoggingConfig) (*LogFile, error) {
	var logFile *LogFile
	fileOutput.Store(nil)

	// Determine output
	output := cfg.Output
	if output == "" {
		output = "stderr"
	}

	// Determine format
	format := cfg.Format
	if format == "" {
		format = "console"
	}

	// Determine level
	level := cfg.Level
	if level == "" {
		level = "info"
	}

	// Parse log level
	slogLevel := parseLogLevel(level)

	// Create handler options
	handlerOpts := &slog.HandlerOptions{
		Level:     slogLevel,
		AddSource: false, // Disabled because wrapper functions report incorrect source locations
	}

	var handler slog.Handler

	// Create handler based on output
	switch output {
	case "stdout":
		if format == "json" {
			handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
		} else {
			handler = slog.NewTextHandler(os.Stdout, handlerOpts)
		}

	case "stderr":
		if format == "json" {
			handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
		} else {
			handler = slog.NewTextHandler(os.Stderr, handlerOpts)
		}

	case "syslog":
		if runtime.GOOS != "windows" {
			syslogWriter, sysErr := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "sora")
			if sysErr != nil {
				// Fall back to stderr if syslog fails
				fmt.Fprintf(os.Stderr, "WARNING: failed to connect to syslog: %v. Falling back to stderr.\n", sysErr)
				if format == "json" {
					handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
				} else {
					handler = slog.NewTextHandler(os.Stderr, handlerOpts)
				}
			} else {
				handler = newSyslogHandler(syslogWriter, slogLevel)
			}
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: syslog is not supported on Windows. Falling back to stderr.\n")
			if format == "json" {
				handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
			} else {
				handler = slog.NewTextHandler(os.Stderr, handlerOpts)
			}
		}

	default:
		// Assume it's a file path
		var err error
		logFile, err = openLogFile(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to open log file '%s': %v. Falling back to stderr.\n", output, err)
			if format == "json" {
				handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
			} else {
				handler = slog.NewTextHandler(os.Stderr, handlerOpts)
			}
			logFile = nil
		} else {
			if format == "json" {
				handler = slog.NewJSONHandler(logFile, handlerOpts)
			} else {
				handler = slog.NewTextHandler(logFile, handlerOpts)
			}
			fileOutput.Store(logFile)
		}
	}

	// Create and set global logger
	l := slog.New(handler)
	globalLogger.Store(l)
	slog.SetDefault(l)
	release(handler) // what was logged since Hold

	return logFile, nil
}

// parseLogLevel converts string log level to slog.Level
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Get returns the global logger instance
func Get() *slog.Logger {
	if l := globalLogger.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// Swap makes l the global logger and returns the previous one (nil before Initialize),
// to hand back to Swap. It is for tests that read what a server logs: they cannot rely on
// where an earlier test's Initialize sent the output.
func Swap(l *slog.Logger) *slog.Logger {
	return globalLogger.Swap(l)
}

// Info logs an info message with optional key-value pairs
func Info(msg string, args ...any) {
	Get().Info(msg, args...)
}

// InfoContext logs an info message with context and optional key-value pairs
func InfoContext(ctx context.Context, msg string, args ...any) {
	Get().InfoContext(ctx, msg, args...)
}

// Debug logs a debug message with optional key-value pairs
func Debug(msg string, args ...any) {
	Get().Debug(msg, args...)
}

// DebugContext logs a debug message with context and optional key-value pairs
func DebugContext(ctx context.Context, msg string, args ...any) {
	Get().DebugContext(ctx, msg, args...)
}

// Warn logs a warning message with optional key-value pairs
func Warn(msg string, args ...any) {
	Get().Warn(msg, args...)
}

// WarnContext logs a warning message with context and optional key-value pairs
func WarnContext(ctx context.Context, msg string, args ...any) {
	Get().WarnContext(ctx, msg, args...)
}

// Error logs an error message with optional key-value pairs
func Error(msg string, args ...any) {
	Get().Error(msg, args...)
}

// ErrorContext logs an error message with context and optional key-value pairs
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Get().ErrorContext(ctx, msg, args...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...any) {
	Get().Error(msg, args...)
	Sync()
	os.Exit(1)
}

// With returns a logger with the given attributes
func With(args ...any) *slog.Logger {
	return Get().With(args...)
}

// Printf provides compatibility with standard log.Printf (logs at Info level)
func Printf(format string, args ...any) {
	Get().Info(fmt.Sprintf(format, args...))
}

// Println provides compatibility with standard log.Println (logs at Info level)
func Println(args ...any) {
	Get().Info(fmt.Sprint(args...))
}

// Infof logs an info message with formatting (compatibility)
func Infof(format string, args ...any) {
	Get().Info(fmt.Sprintf(format, args...))
}

// Debugf logs a debug message with formatting (compatibility)
func Debugf(format string, args ...any) {
	Get().Debug(fmt.Sprintf(format, args...))
}

// Warnf logs a warning message with formatting (compatibility)
func Warnf(format string, args ...any) {
	Get().Warn(fmt.Sprintf(format, args...))
}

// Errorf logs an error message with formatting (compatibility)
func Errorf(format string, args ...any) {
	Get().Error(fmt.Sprintf(format, args...))
}

// Fatalf logs a fatal message with formatting and exits (compatibility)
func Fatalf(format string, args ...any) {
	Get().Error(fmt.Sprintf(format, args...))
	Sync()
	os.Exit(1)
}

// Sync writes to stderr what Hold keeps when Initialize has not run, for a process that
// stops before its logging is configured. Otherwise there is nothing to flush: slog does
// not buffer.
func Sync() error {
	if held.Load() != nil {
		release(slog.NewTextHandler(os.Stderr, nil))
	}
	return nil
}
