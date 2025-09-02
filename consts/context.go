package consts

// ContextKey is a custom type for context keys to avoid collisions between packages.
type ContextKey string

const (
	// UseMasterDBKey is the context key for the "use_master" boolean value.
	// It is used to signal to the database layer that a query should be
	// executed on the primary (write) database connection pool, bypassing
	// the read replica pool. This is crucial for read-your-writes consistency.
	UseMasterDBKey = ContextKey("use_master")
)
