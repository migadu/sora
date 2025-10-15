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
		logger:      log.New(os.Stderr, "[ERROR] ", log.LstdFlags),
	}
}

func (eh *ErrorHandler) FatalError(operation string, err error) {
	gracefulErr := NewGracefulError(operation, err)
	eh.logger.Printf("FATAL: %v", gracefulErr)

	select {
	case eh.exitChannel <- 1:
	default:
	}
}

func (eh *ErrorHandler) ConfigError(configPath string, err error) {
	if os.IsNotExist(err) {
		eh.logger.Printf("ERROR: configuration file '%s' not found: %v", configPath, err)
	} else {
		eh.logger.Printf("ERROR: failed to parse configuration file '%s': %v", configPath, err)
	}

	select {
	case eh.exitChannel <- 1:
	default:
	}
}

func (eh *ErrorHandler) ValidationError(field string, err error) {
	eh.logger.Printf("ERROR: invalid configuration - %s: %v", field, err)

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
