package consts

// SoraAdvisoryLockID was the id of the shared advisory lock every running instance once
// held for its lifetime. Nothing takes that lock any more (its exclusive counterpart in
// sora-admin was removed long ago, and a session-level lock cannot survive a
// transaction-pooling proxy anyway), but the constant stays: SoraMigrationLeaderLockID
// is derived from it, and that id must not change across versions or a rolling restart
// that mixes builds would elect two migration leaders.
const SoraAdvisoryLockID = 42734581 // A randomly chosen integer

// SoraMigrationLeaderLockID is a unique integer used for a PostgreSQL advisory lock
// held by whoever runs migrations: the leader elected among starting instances, and
// sora-admin migrate up/down/force. It is taken transaction-scoped inside a
// db.AdvisoryLockTx.
const SoraMigrationLeaderLockID = SoraAdvisoryLockID + 1

// SoraFTSOrphanSweepLockClassID is the class ID used for transaction-scoped advisory locks
// coordinating FTS delivery staging (shared) and orphan sweep deletion (exclusive).
const SoraFTSOrphanSweepLockClassID = int32(0x46545332) // "FTS2" in hex = 1179997490

// SoraVacationClaimLockClassID separates per-response claims from other users of
// PostgreSQL's two-integer advisory lock namespace.
const SoraVacationClaimLockClassID = int32(0x56414341) // "VACA"

// SoraMailboxACLLockClassID is the class ID of the transaction-scoped advisory lock,
// keyed by hashint8(mailbox_id), that serialises every ACL write on a mailbox.
const SoraMailboxACLLockClassID = int32(0x41434C31) // "ACL1" in hex = 1094929457
