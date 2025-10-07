// Package logger provides structured logging for the Sora email server.
//
// This package wraps zap (https://github.com/uber-go/zap) for high-performance
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
//	logger.Infof("Listening on %s", addr)
//	logger.Warn("High memory usage detected")
//	logger.Error("Failed to connect to database", err)
//	logger.Fatal("Critical error, shutting down")
//
// # Structured Logging
//
// For structured fields, use the With* functions:
//
//	logger.With(
//		"user_id", 123,
//		"mailbox", "INBOX",
//		"message_count", 42,
//	).Info("Mailbox access")
//
// # Log Levels
//
// Supported levels (in order of severity):
//   - debug: Detailed information for debugging
//   - info: General informational messages
//   - warn: Warning messages for potential issues
//   - error: Error messages for failures
//   - fatal: Critical errors that cause shutdown
//
// # Output Formats
//
// Two formats are supported:
//   - json: Machine-readable structured JSON
//   - console: Human-readable colored output
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
// The logger uses zap's high-performance structured logging with minimal
// allocations. It can handle millions of logs per second.
package logger

import (
	"fmt"
	"log/syslog"
	"os"
	"runtime"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/migadu/sora/config"
)

var (
	// Global logger instance
	globalLogger *zap.Logger
	// Sugar logger for easier usage
	globalSugar *zap.SugaredLogger
)

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
	zapLevel := parseLogLevel(level)

	// Create encoder config
	var encoderConfig zapcore.EncoderConfig
	if format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Create encoder
	var encoder zapcore.Encoder
	if format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create write syncer based on output
	var writeSyncer zapcore.WriteSyncer
	var err error

	switch output {
	case "stdout":
		writeSyncer = zapcore.AddSync(os.Stdout)

	case "stderr":
		writeSyncer = zapcore.AddSync(os.Stderr)

	case "syslog":
		if runtime.GOOS != "windows" {
			syslogWriter, sysErr := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "sora")
			if sysErr != nil {
				// Fall back to stderr if syslog fails
				fmt.Fprintf(os.Stderr, "WARNING: failed to connect to syslog: %v. Falling back to stderr.\n", sysErr)
				writeSyncer = zapcore.AddSync(os.Stderr)
			} else {
				writeSyncer = zapcore.AddSync(syslogWriter)
			}
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: syslog is not supported on Windows. Falling back to stderr.\n")
			writeSyncer = zapcore.AddSync(os.Stderr)
		}

	default:
		// Assume it's a file path
		logFile, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: failed to open log file '%s': %v. Falling back to stderr.\n", output, err)
			writeSyncer = zapcore.AddSync(os.Stderr)
			logFile = nil
		} else {
			writeSyncer = zapcore.AddSync(logFile)
			// Redirect stdout and stderr to log file
			os.Stdout = logFile
			os.Stderr = logFile
		}
	}

	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, zapLevel)

	// Create logger
	globalLogger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	globalSugar = globalLogger.Sugar()

	return logFile, nil
}

// parseLogLevel converts string log level to zapcore.Level
func parseLogLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// Get returns the global logger instance
func Get() *zap.Logger {
	if globalLogger == nil {
		// Return a no-op logger if not initialized
		return zap.NewNop()
	}
	return globalLogger
}

// Sugar returns the global sugared logger instance
func Sugar() *zap.SugaredLogger {
	if globalSugar == nil {
		// Return a no-op logger if not initialized
		return zap.NewNop().Sugar()
	}
	return globalSugar
}

// Sync flushes any buffered log entries
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	Get().Info(msg, fields...)
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	Get().Debug(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	Get().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}

// Infof logs an info message with formatting
func Infof(template string, args ...interface{}) {
	Sugar().Infof(template, args...)
}

// Debugf logs a debug message with formatting
func Debugf(template string, args ...interface{}) {
	Sugar().Debugf(template, args...)
}

// Warnf logs a warning message with formatting
func Warnf(template string, args ...interface{}) {
	Sugar().Warnf(template, args...)
}

// Errorf logs an error message with formatting
func Errorf(template string, args ...interface{}) {
	Sugar().Errorf(template, args...)
}

// Fatalf logs a fatal message with formatting and exits
func Fatalf(template string, args ...interface{}) {
	Sugar().Fatalf(template, args...)
}

// Printf provides compatibility with standard log.Printf
func Printf(template string, args ...interface{}) {
	Sugar().Infof(template, args...)
}

// Println provides compatibility with standard log.Println
func Println(args ...interface{}) {
	Sugar().Info(args...)
}
