package errors

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/migadu/sora/logger"
)

type GracefulError struct {
	Operation string
	Err       error
}

func (g *GracefulError) Error() string {
	return fmt.Sprintf("operation '%s' failed: %v", g.Operation, g.Err)
}

func (g *GracefulError) Unwrap() error {
	return g.Err
}

func NewGracefulError(operation string, err error) *GracefulError {
	return &GracefulError{
		Operation: operation,
		Err:       err,
	}
}

type ErrorHandler struct {
	exitChannel chan int
	logger      *log.Logger
}

func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		exitChannel: make(chan int, 1),
		logger:      log.New(logger.Stderr(), "[ERROR] ", log.LstdFlags),
	}
}

// report writes a failure. Once logging is initialized it is an ERROR record (msg and
// args) of the configured logger, so it goes where every other error of the process goes:
// syslog, a JSON log file, ... Before that the output is not known, so line is written to
// stderr after what start-up held (logger.Hold): a configuration file that cannot be read
// is reported this way.
func (eh *ErrorHandler) report(line, msg string, args ...any) {
	if logger.Initialized() {
		logger.Error(msg, args...)
		return
	}
	logger.Sync() // what start-up logged before logging was configured
	eh.logger.Print(line)
}

func (eh *ErrorHandler) FatalError(operation string, err error) {
	eh.report(fmt.Sprintf("FATAL: %v", NewGracefulError(operation, err)),
		"Fatal error", "operation", operation, "error", err)

	select {
	case eh.exitChannel <- 1:
	default:
	}
}

func (eh *ErrorHandler) ConfigError(configPath string, err error) {
	if os.IsNotExist(err) {
		eh.report(fmt.Sprintf("ERROR: configuration file '%s' not found: %v", configPath, err),
			"Configuration file not found", "path", configPath, "error", err)
	} else {
		eh.report(fmt.Sprintf("ERROR: failed to parse configuration file '%s': %v", configPath, err),
			"Failed to parse configuration file", "path", configPath, "error", err)
	}

	select {
	case eh.exitChannel <- 1:
	default:
	}
}

func (eh *ErrorHandler) ValidationError(field string, err error) {
	eh.report(fmt.Sprintf("ERROR: invalid configuration - %s: %v", field, err),
		"Invalid configuration", "field", field, "error", err)

	select {
	case eh.exitChannel <- 1:
	default:
	}
}

func (eh *ErrorHandler) WaitForExit() int {
	return <-eh.exitChannel
}

func (eh *ErrorHandler) WaitForExitWithTimeout(timeout time.Duration) (int, bool) {
	select {
	case code := <-eh.exitChannel:
		return code, true
	case <-time.After(timeout):
		return 0, false
	}
}

func (eh *ErrorHandler) Shutdown(ctx context.Context) {
	select {
	case <-ctx.Done():
		logger.Info("Graceful shutdown initiated")
	default:
		logger.Warn("Unexpected shutdown")
	}
}
