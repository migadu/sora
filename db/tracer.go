package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"
)

// CustomTracer implements the QueryTracer interface. It traces every statement, which
// [database] debug = true asks for, at INFO so that the trace appears without lowering
// the log level of the whole server.
type CustomTracer struct{}

// TraceQueryStart is called at the beginning of Query, QueryRow, and Exec calls.
func (ct *CustomTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	logger.Info("Database: SQL", "sql", data.SQL, "args", data.Args)
	return ctx
}

// TraceQueryEnd is called at the end of Query, QueryRow, and Exec calls.
func (ct *CustomTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err != nil {
		logger.Info("Database: SQL failed", "err", data.Err)
	} else {
		logger.Info("Database: SQL done", "command_tag", data.CommandTag.String())
	}
}
