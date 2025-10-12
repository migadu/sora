package db

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

// CustomTracer implements the QueryTracer interface
type CustomTracer struct{}

// TraceQueryStart is called at the beginning of Query, QueryRow, and Exec calls.
func (ct *CustomTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	log.Printf("[DB] SQL: %s\n-- args: %v", data.SQL, data.Args)
	return ctx
}

// TraceQueryEnd is called at the end of Query, QueryRow, and Exec calls.
func (ct *CustomTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err != nil {
		log.Printf("[DB] ❌ %v", data.Err)
	} else {
		log.Printf("[DB] ✅ %v", data.CommandTag)
	}
}
