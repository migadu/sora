// Package logger provides structured logging for the Sora email server.
//
// This package wraps Go's standard library slog for high-performance
// structured logging with support for multiple outputs:
//   - Console (stdout/stderr)
//   - File (with automatic rotation)
//   - Syslog (local or remote)
//
// # Initialization
//
// Initialize the logger once at application startup:
//
//	cfg := config.LoggingConfig{
//		Output: "file",
//		File:   "/var/log/sora/sora.log",
//		Level:  "info",
//		Format: "json",
//	}
//	logFile, err := logger.Initialize(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer logFile.Close()
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
//		"user_id", 123,
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
// For syslog output:
//
//	cfg := config.LoggingConfig{
//		Output:     "syslog",
//		SyslogAddr: "localhost:514",  // or "/dev/log" for local
//		SyslogTag:  "sora",
//		Level:      "info",
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
	"log/slog"
	"log/syslog"
	"os"
	"runtime"

	"github.com/migadu/sora/config"
)

var (
	// Global logger instance
	globalLogger *slog.Logger
)

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
	msg := r.Message

	// Add attributes
	if len(h.attrs) > 0 || r.NumAttrs() > 0 {
		attrs := make([]any, 0, len(h.attrs)*2+r.NumAttrs()*2)
		for _, a := range h.attrs {
			attrs = append(attrs, a.Key, a.Value.Any())
		}
		r.Attrs(func(a slog.Attr) bool {
			attrs = append(attrs, a.Key, a.Value.Any())
			return true
		})
		if len(attrs) > 0 {
			msg = fmt.Sprintf("%s %v", msg, attrs)
		}
	}

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

// Initialize sets up the global logger based on configuration
func Initialize(cfg config.LoggingConfig) (*os.File, error) {
	var logFile *os.File

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
		logFile, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
			// Redirect stdout and stderr to log file
			os.Stdout = logFile
			os.Stderr = logFile
		}
	}

	// Create and set global logger
	globalLogger = slog.New(handler)
	slog.SetDefault(globalLogger)

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
	if globalLogger == nil {
		return slog.Default()
	}
	return globalLogger
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
	os.Exit(1)
}

// Sync flushes any buffered log entries (no-op for slog, kept for compatibility)
func Sync() error {
	return nil
}
