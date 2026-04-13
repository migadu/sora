package consts

// SoraAdvisoryLockID is a unique integer used for a PostgreSQL advisory lock
// to ensure that only one sora instance or admin tool can perform critical
// operations (like migrations) at a time.
const SoraAdvisoryLockID = 42734581 // A randomly chosen integer

// SoraMigrationLeaderLockID is a unique integer used for a PostgreSQL advisory lock
// exclusively meant for deterministic migration leader election on startup.
const SoraMigrationLeaderLockID = SoraAdvisoryLockID + 1
