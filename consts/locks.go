package consts

// SoraAdvisoryLockID was the id of the shared advisory lock every running instance once
// held for its lifetime. Nothing takes that lock any more (its exclusive counterpart in
// sora-admin was removed long ago, and a session-level lock cannot survive a
// transaction-pooling proxy anyway), but the constant stays: SoraMigrationLeaderLockID
// is derived from it, and that id must not change across versions or a rolling restart
// that mixes builds would elect two migration leaders.
const SoraAdvisoryLockID = 42734581 // A randomly chosen integer

// SoraMigrationLeaderLockID is a unique integer used for a PostgreSQL advisory lock
// exclusively meant for deterministic migration leader election on startup. It is
// taken transaction-scoped inside a db.AdvisoryLockTx.
const SoraMigrationLeaderLockID = SoraAdvisoryLockID + 1
