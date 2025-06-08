# Sora IMAP Server Concurrency Design

This document outlines the concurrency design patterns and best practices for the Sora IMAP server. It serves as a guide for maintaining and extending the codebase with proper concurrency management.

## 1. Overview

The Sora IMAP server handles multiple concurrent client connections, each with its own session state. Each client can issue multiple commands, which may involve accessing and modifying shared resources such as the database and session state.

Proper concurrency management is critical to:
- Prevent race conditions
- Avoid deadlocks
- Maintain data consistency
- Ensure responsive client experience
- Handle client disconnections gracefully

## 2. Core Concurrency Principles

### 2.1 Session State Protection

All access to session state must be protected by the session's mutex. This includes:
- Mailbox selection state
- Sequence number tracking
- Message counts
- Session trackers

### 2.2 Mutex Usage Pattern

Follow this consistent pattern for all command handlers:

1. **State Reading Phase**: Acquire mutex, read necessary state into local variables, release mutex
2. **Processing Phase**: Perform operations (especially I/O and DB operations) outside mutex protection
3. **State Update Phase**: Re-acquire mutex, update session state, release mutex
4. **Context Validation**: Check context validity both before and after mutex acquisition

```go
func (s *IMAPSession) CommandHandler() error {
    // PHASE 1: Read necessary state with mutex protection
    var selectedMailboxID int64
    var sessionTrackerSnapshot *imapserver.SessionTracker
    
    s.mutex.Lock()
    if s.selectedMailbox == nil {
        s.mutex.Unlock()
        return &imap.Error{...}
    }
    selectedMailboxID = s.selectedMailbox.ID
    sessionTrackerSnapshot = s.sessionTracker
    // Use helpers that assume lock is held
    decodedNumSet = s.decodeNumSetLocked(numSet)
    s.mutex.Unlock()
    
    // PHASE 2: Process outside mutex protection
    // Check context before long operations
    if s.ctx.Err() != nil {
        return &imap.Error{...}
    }
    
    results, err := s.server.db.PerformOperation(...)
    if err != nil {
        return s.internalError(...)
    }
    
    // PHASE 3: Update state if needed
    // Check context before updating state
    if s.ctx.Err() != nil {
        return nil // Client disconnected, no need to update state
    }
    
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    // Final context check after acquiring lock
    if s.ctx.Err() != nil {
        return nil
    }
    
    // Update session state
    s.updateState(...)
    
    return nil
}
```

### 2.3 Helper Method Pattern

For methods that need to access protected state and might be called from multiple places:

1. Create a `*Locked` version that assumes the caller holds the mutex
2. Create a public version that acquires the mutex and calls the `*Locked` version

```go
// Helper that assumes mutex is held
func (s *IMAPSession) helperMethodLocked(...) ... {
    // Direct access to protected state
}

// Public method that safely acquires mutex
func (s *IMAPSession) helperMethod(...) ... {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    return s.helperMethodLocked(...)
}
```

### 2.4 Context Handling

All long-running operations must check context validity:

1. Before performing database operations
2. After database operations but before updating session state
3. After acquiring mutex but before updating session state

```go
// Early check before operations
if s.ctx.Err() != nil {
    s.Log("[COMMAND] context cancelled before operation")
    return &imap.Error{...}
}

// Check before state update
if s.ctx.Err() != nil {
    s.Log("[COMMAND] context cancelled after operation, skipping state update")
    return nil
}

// Final check after mutex acquisition
s.mutex.Lock()
defer s.mutex.Unlock()

if s.ctx.Err() != nil {
    s.Log("[COMMAND] context cancelled during mutex acquisition")
    return nil
}
```

### 2.5 State Snapshot Pattern

When a command needs to process multiple items using session state:

1. Take a snapshot of session state once under mutex protection
2. Release the mutex
3. Use the snapshot consistently throughout processing

```go
// Capture snapshot once
s.mutex.Lock()
sessionTrackerSnapshot := s.sessionTracker
s.mutex.Unlock()

// Use snapshot consistently without further locks
for _, item := range items {
    if sessionTrackerSnapshot != nil {
        processedItem := sessionTrackerSnapshot.Process(item)
        // Use processedItem...
    }
}
```

## 3. Command Handler Guidelines

### 3.1 Command Execution Flow

All command handlers should follow this flow:

1. **Validation**: Check if the command can be executed (e.g., mailbox selected)
2. **State Reading**: Read necessary session state under mutex protection
3. **Data Retrieval**: Get data from database without holding mutex
4. **Processing**: Process data and prepare response
5. **State Update**: Update session state if needed, under mutex protection
6. **Response Generation**: Generate response to client

### 3.2 Message Processing

For commands that process multiple messages (FETCH, SEARCH, STORE):

1. Get the list of messages from database outside mutex protection
2. Process messages in a loop, using snapshots of session state consistently
3. Only re-acquire mutex if session state needs to be updated

### 3.3 Flag Updates

For commands that update message flags (STORE):

1. Process flag updates in a loop without holding mutex
2. If response is needed, re-acquire mutex to access current session tracker
3. Generate responses using the current session state

### 3.4 Message Movement

For commands that move messages (MOVE, COPY):

1. Get source and destination mailboxes
2. Process messages outside mutex protection
3. Update session state only if needed
4. Generate expunge responses using snapshot of session state

## 4. Session State Management

### 4.1 Session Fields

The following fields in IMAPSession should be considered protected by mutex:

```go
type IMAPSession struct {
    // Protected fields:
    selectedMailbox *db.DBMailbox
    mailboxTracker  *imapserver.MailboxTracker
    sessionTracker  *imapserver.SessionTracker
    currentHighestModSeq uint64
    currentNumMessages   uint32
    lastSelectedMailboxID int64
    lastHighestUID        imap.UID
    
    // Mutex for protecting the above fields
    mutex sync.Mutex
}
```

### 4.2 Session State Updates

When updating session state:

1. Always acquire mutex before updating any protected field
2. Use deferred unlock to ensure mutex is released even if an error occurs
3. Update related fields atomically (all or none)

```go
s.mutex.Lock()
defer s.mutex.Unlock()

// Update related fields atomically
s.selectedMailbox = mailbox
s.mailboxTracker = tracker
s.currentNumMessages = count
```

### 4.3 Session Closure

When closing a session:

1. Acquire mutex
2. Clear all session state
3. Cancel context to signal all ongoing operations to terminate
4. Release mutex

```go
s.mutex.Lock()
defer s.mutex.Unlock()

s.clearSelectedMailboxStateLocked()

if s.cancel != nil {
    s.cancel()
}
```

## 5. Special Considerations

### 5.1 Deadlock Prevention

To prevent deadlocks:

1. Never call a method that acquires the mutex while already holding the mutex
2. Use the `*Locked` helper pattern for methods that need to be called while holding the mutex
3. Never hold multiple mutexes simultaneously
4. If multiple locks are absolutely necessary, always acquire them in the same order

### 5.2 Long-Running Operations

For long-running operations:

1. Never hold mutex during database operations
2. Never hold mutex during network I/O
3. Check context validity before and after long-running operations
4. Use timeouts for operations that might take too long

### 5.3 Concurrent Updates

When multiple clients might update the same resource:

1. Use database transactions to ensure consistency
2. Verify operation preconditions just before performing the update
3. Handle conflicts gracefully, with appropriate error responses

## 6. Implementation Examples

### 6.1 Example: FETCH Command

```go
func (s *IMAPSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
    // Read state with mutex protection
    var selectedMailboxID int64
    var sessionTrackerSnapshot *imapserver.SessionTracker
    var decodedNumSet imap.NumSet

    s.mutex.Lock()
    if s.selectedMailbox == nil {
        s.mutex.Unlock()
        return &imap.Error{...}
    }
    
    selectedMailboxID = s.selectedMailbox.ID
    sessionTrackerSnapshot = s.sessionTracker
    decodedNumSet = s.decodeNumSetLocked(numSet)
    s.mutex.Unlock()

    // Perform database operation outside mutex protection
    messages, err := s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
    if err != nil {
        return s.internalError(...)
    }

    // Process messages using consistent session state snapshot
    for _, msg := range messages {
        if sessionTrackerSnapshot == nil {
            continue
        }
        
        encodedSeqNum := sessionTrackerSnapshot.EncodeSeqNum(msg.Seq)
        if encodedSeqNum == 0 {
            continue
        }
        
        // Process message...
    }
    
    return nil
}
```

### 6.2 Example: Helper Method Pattern

```go
// Locked version assumes caller holds mutex
func (s *IMAPSession) decodeNumSetLocked(numSet imap.NumSet) imap.NumSet {
    if s.sessionTracker == nil {
        return numSet
    }
    
    // Implementation...
}

// Public version acquires mutex
func (s *IMAPSession) decodeNumSet(numSet imap.NumSet) imap.NumSet {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    return s.decodeNumSetLocked(numSet)
}
```

## 7. RWMutex Usage Pattern

We've replaced standard `sync.Mutex` with `sync.RWMutex` for better performance in read-heavy workloads. This implementation follows these patterns:

### 7.1 Read-Only Operations

For operations that only read session state:

```go
func (s *IMAPSession) readOnlyOperation(...) ... {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    
    // Read session state...
    // Use it for computation...
    
    return result
}
```

### 7.2 State-Modifying Operations

For operations that update session state:

```go
func (s *IMAPSession) stateModifyingOperation(...) ... {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    // Update session state...
    
    return result
}
```

### 7.3 Mixed Operations

For operations that primarily read but occasionally write:

```go
func (s *IMAPSession) mixedOperation(...) ... {
    // First use read lock for all reading
    s.mutex.RLock()
    // Read state into local variables
    value := s.someState
    s.mutex.RUnlock()
    
    // Process data outside lock
    result := processData(value)
    
    // If needed, acquire write lock only for the update
    if needToUpdate {
        s.mutex.Lock()
        s.someState = newValue
        s.mutex.Unlock()
    }
    
    return result
}
```

### 7.4 Helper Methods

Helper methods follow this naming convention:

- `helperLocked`: Requires caller to hold the write lock
- `helperRLocked`: Can be called with either read or write lock

### 7.5 Commands Using Read Locks

These commands primarily use read locks:
- FETCH
- SEARCH
- LIST
- STATUS (except when updating counters)
- EXAMINE
- UID commands

### 7.6 Commands Using Write Locks

These commands require write locks:
- SELECT
- STORE
- APPEND
- EXPUNGE
- CREATE/DELETE
- MOVE/COPY (for state updates)

## 8. Future Considerations

## 7. Replacing Mutex with RWMutex

### 7.1 Rationale for Using RWMutex

After analyzing the concurrency patterns in Sora, we recommend replacing `sync.Mutex` with `sync.RWMutex` for improved performance. This change is justified by the following analysis:

1. **Read-Heavy Workload**: Most IMAP operations predominantly read session state rather than modify it:
   - READ operations: FETCH, SEARCH, LIST, STATUS, EXAMINE
   - WRITE operations: STORE, APPEND, EXPUNGE, SELECT (state changes)

2. **Performance Benefits**:
   - Multiple clients can concurrently read session state without blocking each other
   - Only state-modifying operations would require exclusive locks
   - Significant performance improvement during normal email client usage, where concurrent reads are common

3. **Real-World Usage Patterns**:
   - Email clients often issue multiple simultaneous commands
   - Most common operations (retrieving emails, searching) are read operations
   - Multiple connected clients primarily read their own mailbox state

### 7.2 Implementation Strategy

Replace `sync.Mutex` with `sync.RWMutex` and modify locking patterns as follows:

```go
type IMAPSession struct {
    // ...
    mutex sync.RWMutex  // Replace sync.Mutex
}

// For read-only access - use RLock() for better concurrency
func (s *IMAPSession) readState() {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    // Read state...
}

// For state modification - still use Lock() for exclusive access
func (s *IMAPSession) updateState() {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    // Update state...
}
```

### 7.3 Command Classification by Lock Type

To guide implementation, here's how each IMAP command should use locks:

**Read Lock (RLock/RUnlock) Operations:**
- FETCH - When retrieving messages and translating sequence numbers
- SEARCH - When accessing session state for criteria evaluation
- LIST - When checking mailbox status
- STATUS - When checking mailbox counts and flags
- EXAMINE - When examining mailbox without modifying state
- UID commands - When only accessing sequence number information

**Write Lock (Lock/Unlock) Operations:**
- SELECT - When changing selected mailbox
- STORE - When updating flags that affect session state
- APPEND - When adding messages that change message counts
- EXPUNGE - When removing messages and updating sequence numbers
- CREATE/DELETE - When modifying mailbox structure
- MOVE/COPY - When performing operations that modify message counts

### 7.4 Helper Methods for RWMutex

Update the helper method pattern to use appropriate lock types:

```go
// Read-only helper that assumes caller holds read lock
func (s *IMAPSession) readHelperRLocked(...) ... {
    // Direct read access to protected state
}

// Public read-only method that safely acquires read lock
func (s *IMAPSession) readHelper(...) ... {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    return s.readHelperRLocked(...)
}

// Write helper that assumes caller holds write lock
func (s *IMAPSession) writeHelperLocked(...) ... {
    // Direct write access to protected state
}

// Public write method that safely acquires write lock
func (s *IMAPSession) writeHelper(...) ... {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    return s.writeHelperLocked(...)
}
```

### 7.5 Migration Plan

To safely migrate from `sync.Mutex` to `sync.RWMutex`:

1. **Initial Change**: Replace the mutex type declaration in `IMAPSession`
2. **First Phase**: Convert all existing `Lock()/Unlock()` calls to their `RWMutex` equivalents without changing behavior:
   - Continue using `Lock()/Unlock()` for all operations initially
   - Update helper method names to indicate lock type (e.g., `decodeNumSetRLocked`)
3. **Incremental Conversion**: Methodically convert read-only operations to use `RLock()/RUnlock()`:
   - Start with the most frequently used read operations (FETCH, SEARCH)
   - Test thoroughly after each conversion
   - Measure performance impact
4. **Documentation**: Update method comments to clearly indicate lock requirements

### 7.6 Testing Considerations

Introduce specific tests to verify RWMutex is used correctly:

1. **Concurrent Read Tests**: Verify multiple read operations can proceed simultaneously
2. **Read/Write Contention Tests**: Ensure write operations correctly block and unblock reads
3. **Stress Tests**: Run many concurrent clients with mixed read/write workloads
4. **Benchmarks**: Compare performance before and after RWMutex implementation

### 8. Deadlock Detection

Consider adding deadlock detection in development:

```go
func (s *IMAPSession) acquireMutex(location string) {
    s.Log("[LOCK] Acquiring mutex at %s", location)
    s.mutex.Lock()
    s.Log("[LOCK] Acquired mutex at %s", location)
}

func (s *IMAPSession) releaseMutex(location string) {
    s.Log("[LOCK] Releasing mutex at %s", location)
    s.mutex.Unlock()
}
```

### 9. Structured Logging

Consider adding structured logging for mutex operations:

```go
func (s *IMAPSession) lockLog(action string, fields map[string]interface{}) {
    fields["action"] = action
    fields["goroutine"] = fmt.Sprintf("%p", s)
    s.server.logger.WithFields(fields).Debug("Mutex operation")
}
```

## 10. Conclusion

Consistent application of these concurrency patterns will ensure the Sora IMAP server remains robust, responsive, and free from concurrency bugs. All developers should follow these guidelines when modifying existing code or adding new features.
