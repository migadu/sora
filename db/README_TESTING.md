# Database Testing Guide

This guide explains how to set up and run comprehensive database integration tests for the Sora IMAP server.

## Prerequisites

### 1. PostgreSQL Server
You need a local PostgreSQL server running. Install PostgreSQL:

**macOS (Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**Docker (Alternative):**
```bash
docker run --name postgres-test -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:15
```

### 2. Test Database Setup
The tests will use the existing `sora_mail_db` database. Ensure it exists and has the required extension:

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database if it doesn't exist
CREATE DATABASE sora_mail_db;

# Create pg_trgm extension (required for full-text search)
\c sora_mail_db
CREATE EXTENSION IF NOT EXISTS pg_trgm;
\q
```

**Note:** If you're using a different PostgreSQL user or password, update `config-test.toml` accordingly.

### 3. Configuration
The tests use `config-test.toml` in the project root. This file is already configured for local testing with these defaults:

- **Host:** localhost
- **Port:** 5432  
- **User:** postgres
- **Password:** password
- **Database:** sora_mail_db

If your setup differs, modify `config-test.toml`:

```toml
[database.write]
hosts = ["localhost"]
port = 5432
user = "your_postgres_user"
password = "your_password"  # Add if needed
name = "sora_mail_db"
```

## Running Tests

### Unit Tests Only (No Database)
```bash
# Run unit tests without database integration
go test -short ./db
```

### Integration Tests (With Database)
```bash
# Run all tests including database integration
go test ./db

# Run specific test categories
go test -run "TestAuth" ./db          # Authentication tests
go test -run "TestMessage" ./db       # Message operation tests  
go test -run "TestMailbox" ./db       # Mailbox management tests
go test -run "TestSearch" ./db        # Search functionality tests

# Verbose output
go test -v ./db

# Run specific integration test
go test -run "TestUpdatePassword" ./db
```

### Test with Coverage
```bash
go test -cover ./db
go test -coverprofile=coverage.out ./db
go tool cover -html=coverage.out
```

## Test Structure

### Current Test Coverage

#### ✅ **Authentication Tests** (`auth_test.go`)
- **Unit Tests:**
  - Password hashing (bcrypt, SSHA512, SHA512)
  - Password verification
  - Hash format validation
  - Edge cases (empty passwords, Unicode, etc.)

- **Integration Tests:**
  - `TestUpdatePassword` - Password update functionality
  - `TestGetCredentialForAuth` - User authentication
  - Account creation and credential management

#### ✅ **Message Tests** (`message_test.go`)
- **Unit Tests:**
  - IMAP flag conversion (bitwise ↔ IMAP flags)
  - Message struct validation
  - Flag constant verification

- **Integration Tests (Placeholders):**
  - Message CRUD operations
  - Flag management
  - Message retrieval by criteria

#### ✅ **Mailbox Tests** (`mailbox_test.go`)
- **Unit Tests:**
  - DBMailbox struct validation
  - MailboxSummary testing
  - Constructor functions

- **Integration Tests (Placeholders):**
  - Mailbox creation/deletion
  - Hierarchy management
  - Subscription handling

#### ✅ **Search Tests** (`search_test.go`)
- **Unit Tests:**
  - Search constants
  - Sort criteria validation

- **Integration Tests (Placeholders):**
  - Full-text search
  - Complex query building
  - Performance testing

### Test Categories

**Unit Tests:** Test individual functions without database dependency
- Always run with `go test -short`
- Fast execution
- No external dependencies

**Integration Tests:** Test database operations with real PostgreSQL
- Require test database setup
- Slower execution
- Test real database interactions

## Database Test Infrastructure

### Test Utilities (`testutils/database.go`)
Provides helper functions for database testing:

```go
// Setup test database connection
testDB := testutils.SetupTestDatabase(t)
defer testDB.Cleanup(t)

// Create test account
accountID := testDB.CreateTestAccount(t, "user@example.com", "password")

// Create test mailbox
testDB.CreateTestMailbox(t, accountID, "INBOX")

// Clean all test data
testDB.TruncateAllTables(t)
```

### Test Database Features
- **Automatic migration:** Runs database migrations on setup
- **Extension verification:** Ensures pg_trgm is available
- **Connection management:** Handles database connections
- **Cleanup:** Proper resource cleanup after tests

## Troubleshooting

### Common Issues

**1. Database Connection Error**
```
Failed to connect to test database
```
**Solution:** Ensure PostgreSQL is running and sora_test database exists.

**2. pg_trgm Extension Missing**
```
pg_trgm extension is required but not available
```
**Solution:** Connect to your test database and run:
```sql
CREATE EXTENSION pg_trgm;
```

**3. Permission Denied**
```
permission denied for database
```
**Solution:** Ensure your PostgreSQL user has CREATE privileges:
```sql
GRANT CREATE ON DATABASE sora_test TO your_user;
```

**4. Config File Not Found**
```
config-test.toml not found
```
**Solution:** Ensure `config-test.toml` exists in the project root directory.

### Test Data Cleanup

Tests automatically clean up after themselves, but if you need to manually reset:

```sql
-- Connect to test database
\c sora_test

-- Clear all data (careful!)
TRUNCATE TABLE messages, mailboxes, credentials, accounts CASCADE;
```

## Adding New Tests

### Unit Test Example
```go
func TestNewFunction(t *testing.T) {
    // Unit test - no database required
    result := SomeFunction("input")
    assert.Equal(t, "expected", result)
}
```

### Integration Test Example
```go
func TestDatabaseFunction(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping database integration test in short mode")
    }

    testDB := testutils.SetupTestDatabase(t)
    defer testDB.Cleanup(t)
    
    ctx := context.Background()
    
    // Your test logic here
    result, err := testDB.Database.SomeFunction(ctx, params)
    assert.NoError(t, err)
    assert.NotNil(t, result)
}
```

## Performance Considerations

- **Use transactions:** Most database operations should be in transactions
- **Clean up data:** Use `TruncateAllTables()` for clean test isolation
- **Short mode:** Always check `testing.Short()` for integration tests
- **Resource limits:** Database pools are configured smaller for testing

## CI/CD Integration

For continuous integration, ensure your CI environment:

1. Has PostgreSQL available
2. Creates the test database with pg_trgm extension  
3. Runs tests with appropriate timeout
4. Uses `-short` flag for quick validation

Example CI script:
```bash
# Setup
createdb sora_test
psql sora_test -c "CREATE EXTENSION pg_trgm;"

# Test
go test -short ./db          # Quick unit tests
go test -timeout 5m ./db     # Full integration tests
```

This testing infrastructure provides a solid foundation for maintaining code quality as the Sora IMAP server continues to evolve.