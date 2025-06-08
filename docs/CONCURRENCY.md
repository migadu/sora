# Concurrency Design in Sora IMAP Server

This document outlines the concurrency design patterns used in the Sora IMAP server. It provides guidelines for maintaining thread safety while maximizing parallelism.

## Core Principles

Sora uses a three-phase approach to concurrency management:

1. **Read Phase**: Acquire read locks to safely access shared state
2. **Processing Phase**: Perform computation and database operations outside of locks
3. **Write Phase**: Acquire write locks only when necessary to update shared state

## RWMutex Usage

The `IMAPSession` struct uses `sync.RWMutex` to protect access to session state:

```go
type IMAPSession struct {
    // ...
    mutex sync.RWMutex
    // Session state fields
    // ...
}
```

### When to Use Read Locks (`RLock/RUnlock`)

Use read locks when:
- Reading session state but not modifying it
- Checking server capabilities
- Decoding sequence numbers
- Validating input based on session state

```go
// Example:
s.mutex.RLock()
userID := s.UserID()
hasCapability := s.hasServerCapability(imap.CapCondStore)
s.mutex.RUnlock()
```

### When to Use Write Locks (`Lock/Unlock`)

Use write locks when:
- Modifying session state
- Changing the selected mailbox
- Updating message counts
- Changing tracking structures

```go
// Example:
s.mutex.Lock()
s.currentNumMessages = newCount
s.mutex.Unlock()
```

## Helper Methods

The codebase includes helper methods for common operations that need lock protection:

```go
// Helper for checking server capabilities with proper locking
func (s *IMAPSession) hasServerCapability(cap imap.Cap) bool {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    _, has := s.server.caps[cap]
    return has
}

// Helper for decoding sequence numbers with proper locking
func (s *IMAPSession) decodeNumSet(numSet imap.NumSet) imap.NumSet {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    return s.decodeNumSetLocked(numSet)
}
```

## Command Handler Pattern

IMAP command handlers should follow this pattern:

```go
func (s *IMAPSession) CommandName(...) error {
    // 1. Read Phase: Read session state with read lock
    s.mutex.RLock()
    userID := s.UserID()
    mailboxID := s.selectedMailbox.ID // If needed
    // Make local copies of any other needed state
    s.mutex.RUnlock()
    
    // 2. Processing Phase: Perform operations without locks
    // - Database operations
    // - Computations
    // - Data transformations
    
    // 3. Write Phase (if needed): Update session state with write lock
    s.mutex.Lock()
    // Update session state
    s.mutex.Unlock()
    
    return nil
}
```

## Common Anti-Patterns to Avoid

1. **Lock Upgrade**: Never try to upgrade from a read lock to a write lock without first releasing the read lock
   ```go
   // BAD
   s.mutex.RLock()
   // ... do some reading
   s.mutex.Lock() // DEADLOCK RISK! Trying to upgrade from read to write lock
   // ... do some writing
   s.mutex.Unlock()
   s.mutex.RUnlock()
   
   // GOOD
   s.mutex.RLock()
   // ... do some reading
   s.mutex.RUnlock()
   
   s.mutex.Lock()
   // ... do some writing
   s.mutex.Unlock()
   ```

2. **Extended Lock Duration**: Avoid holding locks during long operations
   ```go
   // BAD
   s.mutex.Lock()
   defer s.mutex.Unlock()
   // Database query or network I/O here - Lock held too long!
   
   // GOOD
   s.mutex.RLock()
   userID := s.UserID()
   s.mutex.RUnlock()
   
   // Database query or network I/O here - No lock held
   ```

3. **Unnecessary Write Locks**: Don't use write locks when read locks would suffice
   ```go
   // BAD
   s.mutex.Lock()
   userID := s.UserID() // Just reading, doesn't need write lock
   s.mutex.Unlock()
   
   // GOOD
   s.mutex.RLock()
   userID := s.UserID()
   s.mutex.RUnlock()
   ```

## Testing for Concurrency Issues

When reviewing code for concurrency issues, check for:

1. Any database or network operations performed while holding locks
2. Lock upgrades (read → write without releasing)
3. Unnecessarily long lock durations
4. Holding locks across callbacks or asynchronous operations

## Recent Improvements

The codebase has been updated to follow these guidelines more consistently:

1. All command handlers have been restructured to follow the three-phase pattern
2. Helper methods have been added for common operations requiring locks
3. Lock durations have been minimized by only locking around critical sections
4. Proper separation between read and write operations has been enforced

These changes have improved the server's concurrency characteristics, making it more responsive under load and less susceptible to deadlocks.
