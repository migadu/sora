# HTTP User API Integration Tests

Comprehensive integration tests for the HTTP User API that provides RESTful access to mailboxes via HTTP with JWT authentication.

## Overview

These tests verify the complete HTTP User API implementation including:
- JWT authentication (login, token refresh, error handling)
- Mailbox operations (CRUD, subscribe/unsubscribe, hierarchical mailboxes)
- Message operations (list, search, retrieve, update flags, delete)
- Message body retrieval (HTML, text, raw RFC822)
- Sieve filter management (CRUD, activate, capabilities)
- Search functionality (basic, filtered, unseen-only)
- Error handling and edge cases
- Authorization and security

## Prerequisites

- PostgreSQL database running on localhost:5432
- Database name: `sora_mail_db`
- User: `postgres` (no password for local testing)

## Running Tests

### Run all HTTP User API tests:
```bash
go test -v -tags=integration ./integration_tests/httpuserapi/
```

### Run specific test suites:
```bash
# Authentication tests
go test -v -tags=integration ./integration_tests/httpuserapi/ -run TestAuthentication

# Mailbox tests
go test -v -tags=integration ./integration_tests/httpuserapi/ -run TestMailbox

# Message tests
go test -v -tags=integration ./integration_tests/httpuserapi/ -run TestMessage

# Sieve filter tests
go test -v -tags=integration ./integration_tests/httpuserapi/ -run TestSieve

# Search tests
go test -v -tags=integration ./integration_tests/httpuserapi/ -run TestSearch
```

### Skip tests if database unavailable:
```bash
SKIP_INTEGRATION_TESTS=1 go test -v -tags=integration ./integration_tests/httpuserapi/
```

## Test Coverage

### Authentication Tests (`TestAuthentication`)
- ✅ Successful login with valid credentials
- ✅ Login rejection with invalid password
- ✅ Login rejection for non-existent user
- ✅ Token refresh functionality (exchange valid token for new one)
- ✅ Token validation and expiration

### Authentication Edge Cases (`TestAuthenticationEdgeCases`)
- ✅ Missing email field
- ✅ Missing password field
- ✅ Empty credentials
- ✅ Invalid JWT token format
- ✅ Missing token on refresh

### Mailbox Operation Tests (`TestMailboxOperations`)
- ✅ List all mailboxes with message counts
- ✅ Create new mailbox
- ✅ Protection of INBOX from deletion
- ✅ Unauthorized access without JWT token

### Mailbox Subscription Tests (`TestMailboxSubscriptions`)
- ✅ Subscribe to mailbox
- ✅ Unsubscribe from mailbox
- ✅ List subscribed mailboxes only

### Mailbox Edge Cases (`TestMailboxEdgeCases`)
- ✅ Duplicate mailbox name rejection
- ✅ Empty mailbox name validation
- ✅ Non-existent mailbox deletion handling
- ✅ Hierarchical mailbox names (Parent/Child)

### Message Operation Tests (`TestMessageOperations`)
- ✅ List messages in empty mailbox
- ✅ List messages with pagination (limit, offset)
- ✅ Search messages with query
- ✅ Missing query parameter validation

### Message Retrieval Tests (`TestMessageRetrieval`)
- ✅ Get full message details (JSON)
- ✅ Get message body (default format)
- ✅ Get message body as HTML
- ✅ Get message body as plain text
- ✅ Get raw RFC822 message
- ✅ Content-Type header validation for raw messages

### Message Flag Tests (`TestMessageFlags`)
- ✅ Add flags to message (Seen, Flagged, etc.)
- ✅ Remove flags from message (Draft, etc.)
- ✅ Add and remove flags in single request
- ✅ Delete message (mark as deleted and expunge)

### Sieve Filter Tests (`TestSieveFilters`)
- ✅ List filters (initially empty)
- ✅ Create new Sieve filter script
- ✅ Retrieve specific filter by name
- ✅ Update existing filter content
- ✅ Activate filter script
- ✅ Get Sieve capabilities and extensions
- ✅ Delete filter script
- ✅ Verify deletion (404 on get)

### Search Functionality Tests (`TestSearchFunctionality`)
- ✅ Basic text search query
- ✅ Search with sender (from) filter
- ✅ Search with subject filter
- ✅ Search unseen messages only
- ✅ Search in non-existent mailbox (404 handling)

## Test Infrastructure

### TestContext
Provides common test infrastructure:
- HTTP test server with JWT authentication
- Database connection (ResilientDatabase)
- Test user account
- HTTP client with JWT token management

### Helper Functions
- `setupTestServer()` - Creates test server and database
- `makeRequest()` - Makes authenticated HTTP requests
- `parseJSON()` - Parses JSON responses

## API Endpoints Tested

### Public Endpoints (No Auth)
- `POST /user/v1/auth/login` - Authenticate and get JWT
- `POST /user/v1/auth/refresh` - Refresh JWT token

### Protected Endpoints (Require JWT)

#### Mailboxes
- `GET /user/v1/mailboxes` - List mailboxes (with ?subscribed=true filter)
- `POST /user/v1/mailboxes` - Create new mailbox
- `DELETE /user/v1/mailboxes/{name}` - Delete mailbox
- `POST /user/v1/mailboxes/{name}/subscribe` - Subscribe to mailbox
- `POST /user/v1/mailboxes/{name}/unsubscribe` - Unsubscribe from mailbox

#### Messages
- `GET /user/v1/mailboxes/{name}/messages` - List messages (with pagination)
- `GET /user/v1/mailboxes/{name}/search` - Search messages (with filters)
- `GET /user/v1/messages/{id}` - Get message details (JSON)
- `GET /user/v1/messages/{id}/body` - Get message body (HTML or text)
- `GET /user/v1/messages/{id}/raw` - Get raw RFC822 message
- `PATCH /user/v1/messages/{id}` - Update message flags
- `DELETE /user/v1/messages/{id}` - Delete message

#### Sieve Filters
- `GET /user/v1/filters` - List all filter scripts
- `GET /user/v1/filters/{name}` - Get specific filter script
- `PUT /user/v1/filters/{name}` - Create or update filter script
- `DELETE /user/v1/filters/{name}` - Delete filter script
- `POST /user/v1/filters/{name}/activate` - Activate filter script
- `GET /user/v1/filters/capabilities` - Get Sieve capabilities

## Example Test Output

```
=== RUN   TestAuthentication
=== RUN   TestAuthentication/Login_Success
    httpuserapi_test.go:155: Successfully obtained JWT token
=== RUN   TestAuthentication/Login_InvalidPassword
=== RUN   TestAuthentication/Login_NonexistentUser
=== RUN   TestAuthentication/RefreshToken_Success
    httpuserapi_test.go:217: Successfully refreshed JWT token
--- PASS: TestAuthentication (2.15s)
    --- PASS: TestAuthentication/Login_Success (0.52s)
    --- PASS: TestAuthentication/Login_InvalidPassword (0.48s)
    --- PASS: TestAuthentication/Login_NonexistentUser (0.42s)
    --- PASS: TestAuthentication/RefreshToken_Success (1.73s)
```

## Notes

- Tests use unique email addresses per test run to avoid conflicts
- Each test creates its own isolated test account
- Tests automatically clean up resources on completion
- Database transactions are used where applicable
- Tests can run concurrently with proper isolation

## Troubleshooting

### Database Connection Errors
If you see database connection errors:
1. Ensure PostgreSQL is running: `pg_isready`
2. Check database exists: `psql -l | grep sora_mail_db`
3. Verify connection: `psql -U postgres -d sora_mail_db -c "SELECT 1"`

### Test Failures
- Check logs for detailed error messages
- Use `-v` flag for verbose output
- Run individual tests to isolate issues
- Verify database schema is up to date

## Test Statistics

- **9 Test Suites** covering all major functionality
- **50+ Individual Test Cases** with comprehensive coverage
- Tests cover success paths, error cases, and edge conditions
- Full coverage of authentication, mailboxes, messages, and filters

## Related Documentation

- [server/userapi/](../../server/userapi/) - HTTP User API implementation
- [server/userapi/user_api_openapi.yaml](../../server/userapi/user_api_openapi.yaml) - OpenAPI specification
- [integration_tests/common/](../common/) - Shared test utilities
- [CLAUDE.md](../../CLAUDE.md) - Project development guide
