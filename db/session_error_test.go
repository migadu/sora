package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Severity describes session lifetime independently of SQLSTATE. A fatal
// lock-related error must not be mistaken for an ordinary lock timeout.
func TestSessionEndingSeverityPrecedesLockTimeout(t *testing.T) {
	cases := []struct {
		name, severity, unlocalized, code string
		want                              error
	}{
		{"fatal lock code", "FATAL", "", "55P03", ErrConnectionClosed},
		{"panic lock code", "PANIC", "", "55P03", ErrConnectionClosed},
		{"localized fatal lock code", "ВАЖНО", "FATAL", "55P03", ErrConnectionClosed},
		{"ordinary lock timeout", "ERROR", "ERROR", "55P03", ErrDBLockTimeout},
		{"unlocalized severity wins", "FATAL", "ERROR", "55P03", ErrDBLockTimeout},
		{"ordinary protocol error", "ERROR", "ERROR", "08P01", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause := &pgconn.PgError{Severity: tc.severity, SeverityUnlocalized: tc.unlocalized, Code: tc.code, Message: "review error"}
			wrapped := fmt.Errorf("database operation: %w", cause)
			got := ClassifyDBError(wrapped)
			for _, sentinel := range []error{ErrConnectionClosed, ErrDBLockTimeout} {
				if errors.Is(got, sentinel) != (tc.want == sentinel) {
					t.Errorf("ClassifyDBError = %v, sentinel %v, want %v", got, sentinel, tc.want)
				}
			}
			if !errors.Is(got, wrapped) {
				t.Errorf("wrapped error lost: %v", got)
			}
			var pgErr *pgconn.PgError
			if !errors.As(got, &pgErr) || pgErr != cause {
				t.Errorf("structured cause lost: %v", got)
			}
			if tc.want == nil && got != wrapped {
				t.Errorf("ordinary statement error changed: %v", got)
			}
		})
	}
}
