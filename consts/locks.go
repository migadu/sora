package consts

// SoraAdvisoryLockID is a unique integer used for a PostgreSQL advisory lock
// to ensure that only one sora instance or admin tool can perform critical
// operations (like migrations) at a time.
const SoraAdvisoryLockID = 42734581 // A randomly chosen integer
