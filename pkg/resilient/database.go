package resilient

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
)

type ResilientDatabase struct {
	database     *db.Database
	queryBreaker *circuitbreaker.CircuitBreaker
	writeBreaker *circuitbreaker.CircuitBreaker
}

func NewResilientDatabase(database *db.Database) *ResilientDatabase {
	querySettings := circuitbreaker.DefaultSettings("database_query")
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.5
	}
	querySettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("Database query circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	writeSettings := circuitbreaker.DefaultSettings("database_write")
	writeSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 3 && failureRatio >= 0.4
	}
	writeSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("Database write circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	return &ResilientDatabase{
		database:     database,
		queryBreaker: circuitbreaker.NewCircuitBreaker(querySettings),
		writeBreaker: circuitbreaker.NewCircuitBreaker(writeSettings),
	}
}

func (rd *ResilientDatabase) GetDatabase() *db.Database {
	return rd.database
}

func (rd *ResilientDatabase) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	
	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"i/o timeout",
		"network unreachable",
		"no such host",
		"temporary failure",
		"too many connections",
		"server closed the connection",
		"broken pipe",
		"connection lost",
	}

	for _, retryable := range retryableErrors {
		if len(errStr) >= len(retryable) {
			for i := 0; i <= len(errStr)-len(retryable); i++ {
				if errStr[i:i+len(retryable)] == retryable {
					return true
				}
			}
		}
	}

	return false
}

func (rd *ResilientDatabase) QueryWithRetry(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var rows pgx.Rows
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			r, queryErr := rd.database.ReadPool.Query(ctx, sql, args...)
			return r, queryErr
		})
		
		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}
		
		rows = result.(pgx.Rows)
		return nil
	}, config)

	return rows, err
}

func (rd *ResilientDatabase) QueryRowWithRetry(ctx context.Context, sql string, args ...interface{}) (pgx.Row, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var row pgx.Row
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			r := rd.database.ReadPool.QueryRow(ctx, sql, args...)
			return r, nil
		})
		
		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}
		
		row = result.(pgx.Row)
		return nil
	}, config)

	return row, err
}

func (rd *ResilientDatabase) ExecWithRetry(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2,
	}

	var tag pgconn.CommandTag
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			t, execErr := rd.database.WritePool.Exec(ctx, sql, args...)
			return t, execErr
		})
		
		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}
		
		tag = result.(pgconn.CommandTag)
		return nil
	}, config)

	return tag, err
}

func (rd *ResilientDatabase) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2,
	}

	var tx pgx.Tx
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			t, txErr := rd.database.WritePool.BeginTx(ctx, txOptions)
			return t, txErr
		})
		
		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}
		
		tx = result.(pgx.Tx)
		return nil
	}, config)

	return tx, err
}

func (rd *ResilientDatabase) Close() {
	rd.database.Close()
}

func (rd *ResilientDatabase) GetQueryBreakerState() circuitbreaker.State {
	return rd.queryBreaker.State()
}

func (rd *ResilientDatabase) GetWriteBreakerState() circuitbreaker.State {
	return rd.writeBreaker.State()
}