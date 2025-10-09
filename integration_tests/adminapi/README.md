# HTTP Admin API Integration Tests

This directory contains comprehensive integration tests for the Sora HTTP Admin API server (`http_admin_api` server type).

**Base Path:** `/admin/*`

**Authentication:** API key (Bearer token)

## Test Coverage

### **Account Management**
- ✅ Full CRUD operations (Create, Read, Update, Delete)
- ✅ Account existence checking
- ✅ Multi-credential account creation
- ✅ Account soft delete and restore
- ✅ Account lifecycle management

### **Credential Management** 
- ✅ Adding secondary credentials
- ✅ Listing account credentials
- ✅ Getting credential details
- ✅ Deleting credentials (with primary protection)
- ✅ Duplicate credential handling

### **Connection Management**
- ✅ Listing active connections
- ✅ Connection statistics
- ✅ Connection termination by criteria
- ✅ User-specific connection queries

### **Cache Management**
- ✅ Cache statistics retrieval
- ✅ Cache metrics (latest and historical)
- ✅ Cache purging operations

### **Health Monitoring**
- ✅ System health overview
- ✅ Host-specific health status
- ✅ Component health status
- ✅ Health history retrieval

### **Uploader Monitoring**
- ✅ Uploader status and statistics
- ✅ Failed upload tracking
- ✅ Failed upload limiting

### **Authentication Statistics**
- ✅ Auth attempt statistics
- ✅ Custom time window queries

### **System Configuration**
- ✅ API feature discovery
- ✅ Endpoint enumeration

### **Message Restoration**
- ✅ List deleted messages
- ✅ Filter by mailbox
- ✅ Restore by message IDs
- ✅ Restore by mailbox
- ✅ Pagination support

### **Error Scenarios**
- ✅ Authentication failures (missing/invalid API key)
- ✅ Resource not found errors
- ✅ Duplicate resource creation
- ✅ Invalid input validation
- ✅ Parameter parsing errors
- ✅ Edge cases and boundary conditions

## Test Structure

### **Setup**
- Creates isolated test database per test run
- Sets up HTTP API server on random port
- Configures test cache instance
- Provides helper functions for HTTP requests

### **Test Categories**

1. **TestAccountCRUD** - Basic account operations
2. **TestMultiCredentialAccount** - Multi-credential scenarios
3. **TestConnectionManagement** - Connection tracking and management
4. **TestCacheManagement** - Cache operations and statistics
5. **TestHealthMonitoring** - System health endpoints
6. **TestUploaderMonitoring** - Upload tracking and statistics
7. **TestAuthStatistics** - Authentication metrics
8. **TestSystemConfiguration** - API metadata and configuration
9. **TestErrorScenarios** - Error handling and validation
10. **TestCredentialManagementEdgeCases** - Advanced credential scenarios
11. **TestAccountLifecycle** - Complete account workflow
12. **TestMessageRestoration** - Deleted message restoration

### **Key Features**

- **Real Database Integration** - Tests against actual PostgreSQL database
- **HTTP Server Integration** - Full HTTP API server startup and testing
- **Authentication Testing** - API key validation and security
- **Error Scenario Coverage** - Comprehensive error handling validation
- **Resource Cleanup** - Automatic test isolation and cleanup
- **Detailed Assertions** - Response validation and structure checking

## Running the Tests

```bash
# Run all HTTP API integration tests
go test -tags=integration ./integration_tests/httpapi/

# Run with verbose output
go test -v -tags=integration ./integration_tests/httpapi/

# Run specific test
go test -tags=integration ./integration_tests/httpapi/ -run TestAccountCRUD
```

## Prerequisites

- PostgreSQL database available at localhost:5432
- Database named `sora_mail_db` 
- User `postgres` with access
- Go 1.23.1+

## Test Data

Tests create unique email addresses using timestamps to avoid conflicts:
- `test-crud-{timestamp}@example.com`
- `primary-{timestamp}@example.com`
- `lifecycle-test-{timestamp}@example.com`

All test data is automatically cleaned up after test completion.

## Integration with CI/CD

These tests are designed to run in continuous integration environments:
- No external dependencies beyond PostgreSQL
- Automatic port allocation prevents conflicts
- Deterministic test execution
- Comprehensive error reporting

The integration tests provide confidence that the HTTP API works correctly end-to-end with real database operations and HTTP communication.