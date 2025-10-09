# Sora Admin API Documentation

The Sora Admin API provides a RESTful HTTP interface for managing and monitoring the Sora mail server. This API enables programmatic administration of accounts, connections, cache, health monitoring, and mail delivery.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Base URL](#base-url)
- [API Endpoints](#api-endpoints)
  - [Account Management](#account-management)
  - [Credential Management](#credential-management)
  - [Connection Management](#connection-management)
  - [Cache Management](#cache-management)
  - [Uploader Monitoring](#uploader-monitoring)
  - [Authentication Statistics](#authentication-statistics)
  - [Health Monitoring](#health-monitoring)
  - [System Configuration](#system-configuration)
  - [Mail Delivery](#mail-delivery)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [Rate Limiting](#rate-limiting)

## Overview

The Admin API is designed for:
- **System Administrators**: Manage user accounts and monitor system health
- **Operations Teams**: Monitor connections, cache performance, and upload status
- **Automation Tools**: Programmatic account provisioning and mail delivery
- **Monitoring Systems**: Health checks and metrics collection

**Key Features:**
- RESTful design with JSON request/response
- API key authentication
- Comprehensive error responses
- OpenAPI 3.0 specification available

## Authentication

All Admin API requests require authentication using an API key passed in the `Authorization` header as a Bearer token.

### Generating an API Key

Configure the API key in your `config.toml`:

```toml
[servers.http_admin_api]
start = true
addr = "127.0.0.1:8080"
api_key = "your-secret-api-key-here"  # Generate a strong random key
tls = false
```

**Security Best Practices:**
- Use a cryptographically secure random string (at least 32 characters)
- Never commit API keys to version control
- Use environment variables or secrets management
- Rotate keys periodically
- Use TLS in production

### Making Authenticated Requests

Include the API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer your-secret-api-key-here" \
     http://localhost:8080/admin/v1/accounts
```

**Response on Invalid/Missing API Key:**
```json
{
  "error": "Unauthorized"
}
```
HTTP Status: `401 Unauthorized`

## Base URL

The default base URL depends on your configuration:

- **Development**: `http://localhost:8080/admin/v1`
- **Production**: `https://your-domain.com/admin/v1`

All endpoints are prefixed with `/admin/v1/`.

## API Endpoints

### Account Management

Manage email accounts including creation, retrieval, updates, and deletion.

#### Create Account

**Endpoint:** `POST /admin/v1/accounts`

Create a new email account with either a single credential or multiple credentials.

**Request Body (Single Credential):**
```json
{
  "email": "user@example.com",
  "password": "secure-password"
}
```

**Request Body (Multiple Credentials):**
```json
{
  "credentials": [
    {
      "email": "primary@example.com",
      "password": "password1",
      "is_primary": true
    },
    {
      "email": "alias@example.com",
      "password": "password2",
      "is_primary": false
    }
  ]
}
```

**Request Body (With Pre-hashed Password):**
```json
{
  "email": "user@example.com",
  "password_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewtsJh.2gUOhvY66"
}
```

**Response:** `201 Created`
```json
{
  "account_id": 123,
  "email": "user@example.com",
  "message": "Account created successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/admin/v1/accounts \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Get Account Details

**Endpoint:** `GET /admin/v1/accounts/{email}`

Retrieve detailed information about an account including credentials, mailbox count, and message count.

**Response:** `200 OK`
```json
{
  "account_id": 123,
  "created_at": "2024-01-15T10:30:00Z",
  "deleted_at": null,
  "primary_email": "user@example.com",
  "status": "active",
  "credentials": [
    {
      "address": "user@example.com",
      "primary_identity": true,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    },
    {
      "address": "alias@example.com",
      "primary_identity": false,
      "created_at": "2024-01-16T14:20:00Z",
      "updated_at": "2024-01-16T14:20:00Z"
    }
  ],
  "mailbox_count": 5,
  "message_count": 142
}
```

**Example:**
```bash
curl http://localhost:8080/admin/v1/accounts/user@example.com \
  -H "Authorization: Bearer your-api-key"
```

#### Update Account Password

**Endpoint:** `PUT /admin/v1/accounts/{email}`

Update the password for a specific credential.

**Request Body:**
```json
{
  "password": "new-secure-password"
}
```

**Or with pre-hashed password:**
```json
{
  "password_hash": "$2a$12$NewHashedPassword..."
}
```

**Response:** `200 OK`
```json
{
  "message": "Account updated successfully"
}
```

**Example:**
```bash
curl -X PUT http://localhost:8080/admin/v1/accounts/user@example.com \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewPassword456!"
  }'
```

#### Delete Account (Soft Delete)

**Endpoint:** `DELETE /admin/v1/accounts/{email}`

Soft delete an account. The account is marked as deleted but data is retained during the grace period.

**Response:** `200 OK`
```json
{
  "email": "user@example.com",
  "message": "Account soft-deleted successfully. It will be permanently removed after the grace period."
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8080/admin/v1/accounts/user@example.com \
  -H "Authorization: Bearer your-api-key"
```

#### Restore Deleted Account

**Endpoint:** `POST /admin/v1/accounts/{email}/restore`

Restore a soft-deleted account within the grace period.

**Response:** `200 OK`
```json
{
  "email": "user@example.com",
  "message": "Account restored successfully."
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/admin/v1/accounts/user@example.com/restore \
  -H "Authorization: Bearer your-api-key"
```

#### Check Account Existence

**Endpoint:** `GET /admin/v1/accounts/{email}/exists`

Check if a credential with the given email exists.

**Response:** `200 OK`
```json
{
  "email": "user@example.com",
  "exists": true
}
```

**Example:**
```bash
curl http://localhost:8080/admin/v1/accounts/user@example.com/exists \
  -H "Authorization: Bearer your-api-key"
```

#### Add Credential (Alias) to Account

**Endpoint:** `POST /admin/v1/accounts/{email}/credentials`

Add a new email alias to an existing account.

**Request Body:**
```json
{
  "email": "newalias@example.com",
  "password": "alias-password"
}
```

**Response:** `201 Created`
```json
{
  "email": "newalias@example.com",
  "message": "Credential added successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/admin/v1/accounts/user@example.com/credentials \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alias@example.com",
    "password": "AliasPassword789!"
  }'
```

### Credential Management

Manage individual credentials (email addresses) associated with accounts.

#### Get Credential Details

**Endpoint:** `GET /admin/v1/credentials/{email}`

Retrieve detailed information about a specific credential and its associated account.

**Response:** `200 OK`
```json
{
  "address": "user@example.com",
  "primary_identity": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "account": {
    "account_id": 123,
    "account_created_at": "2024-01-15T10:30:00Z",
    "account_deleted_at": null,
    "account_status": "active",
    "mailbox_count": 5,
    "message_count": 142,
    "total_credentials": 3
  }
}
```

#### Delete Credential

**Endpoint:** `DELETE /admin/v1/credentials/{email}`

Delete a specific credential. Cannot delete primary or last remaining credential.

**Response:** `200 OK`
```json
{
  "email": "alias@example.com",
  "message": "Credential deleted successfully"
}
```

### Connection Management

Monitor and manage active client connections to the mail server.

#### List Active Connections

**Endpoint:** `GET /admin/v1/connections`

Retrieve all active connections across all protocols.

**Response:** `200 OK`
```json
{
  "connections": [
    {
      "ID": 1,
      "AccountID": 123,
      "Protocol": "IMAP",
      "ClientAddr": "192.168.1.100:54321",
      "ServerAddr": "10.0.1.10:143",
      "InstanceID": "sora-instance-1",
      "ConnectedAt": "2024-01-20T09:15:00Z",
      "LastActivity": "2024-01-20T09:20:00Z",
      "ShouldTerminate": false,
      "Email": "user@example.com"
    }
  ],
  "count": 1
}
```

#### Get Connection Statistics

**Endpoint:** `GET /admin/v1/connections/stats`

Get aggregated statistics about active connections.

**Response:** `200 OK`
```json
{
  "TotalConnections": 150,
  "ConnectionsByProtocol": {
    "IMAP": 120,
    "POP3": 20,
    "ManageSieve": 10
  },
  "ConnectionsByServer": {
    "10.0.1.10:143": 80,
    "10.0.1.11:143": 70
  },
  "Users": [...]
}
```

#### Terminate Connections

**Endpoint:** `POST /admin/v1/connections/kick`

Mark connections for termination based on criteria.

**Request Body:**
```json
{
  "user_email": "user@example.com",
  "protocol": "IMAP",
  "server_addr": "10.0.1.10:143",
  "client_addr": "192.168.1.100",
  "all": false
}
```

**Response:** `200 OK`
```json
{
  "message": "Connections marked for termination",
  "connections_marked": 5
}
```

**Example (Kick all connections for a user):**
```bash
curl -X POST http://localhost:8080/admin/v1/connections/kick \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "user@example.com"
  }'
```

#### Get User Connections

**Endpoint:** `GET /admin/v1/connections/user/{email}`

Get all active connections for a specific user.

**Response:** `200 OK`
```json
{
  "email": "user@example.com",
  "connections": [...],
  "count": 3
}
```

### Cache Management

Monitor and manage the local filesystem cache for message bodies.

#### Get Cache Statistics

**Endpoint:** `GET /admin/v1/cache/stats`

Get current cache statistics including size, items, and hit/miss ratios.

**Response:** `200 OK`
```json
{
  "total_size": 524288000,
  "items": 1523,
  "hits": 45678,
  "misses": 3421,
  "hit_rate": 0.93,
  "capacity": 1073741824,
  "path": "/var/sora/cache"
}
```

#### Get Cache Performance Metrics

**Endpoint:** `GET /admin/v1/cache/metrics`

Get historical cache performance metrics.

**Query Parameters:**
- `latest=true` - Return only the latest metric for each instance
- `instance_id=xyz` - Filter by instance ID
- `since=2024-01-20T00:00:00Z` - Return metrics after this timestamp
- `limit=100` - Maximum records to return

**Response:** `200 OK`
```json
{
  "metrics": [
    {
      "instance_id": "sora-instance-1",
      "server_hostname": "mail-server-01",
      "hits": 45678,
      "misses": 3421,
      "hit_rate": 0.93,
      "total_operations": 49099,
      "uptime_seconds": 86400,
      "recorded_at": "2024-01-20T10:00:00Z"
    }
  ],
  "count": 1
}
```

#### Purge Cache

**Endpoint:** `POST /admin/v1/cache/purge`

Clear the entire cache. Returns statistics before and after purge.

**Response:** `200 OK`
```json
{
  "message": "Cache purged successfully",
  "stats_before": {
    "total_size": 524288000,
    "items": 1523
  },
  "stats_after": {
    "total_size": 0,
    "items": 0
  }
}
```

### Uploader Monitoring

Monitor the background S3 upload queue and failed uploads.

#### Get Uploader Status

**Endpoint:** `GET /admin/v1/uploader/status`

Get status of the S3 upload queue.

**Query Parameters:**
- `show_failed=true` - Include list of recent failed uploads
- `max_attempts=5` - Failure threshold
- `failed_limit=10` - Limit failed uploads returned

**Response:** `200 OK`
```json
{
  "stats": {
    "pending_count": 15,
    "failed_count": 2,
    "in_progress_count": 3,
    "total_processed": 45678,
    "last_successful_upload": "2024-01-20T10:15:00Z",
    "last_failed_upload": "2024-01-20T09:30:00Z"
  },
  "failed_uploads": [...],
  "failed_count": 2
}
```

#### Get Failed Uploads

**Endpoint:** `GET /admin/v1/uploader/failed`

Get list of failed S3 uploads.

**Query Parameters:**
- `max_attempts=5` - Failure threshold
- `limit=50` - Maximum records to return

**Response:** `200 OK`
```json
{
  "failed_uploads": [
    {
      "id": 123,
      "content_hash": "blake3_abc123...",
      "account_id": 456,
      "size": 102400,
      "attempts": 6,
      "last_attempt": "2024-01-20T09:30:00Z",
      "last_error": "Connection timeout to S3"
    }
  ],
  "count": 1
}
```

### Authentication Statistics

Monitor authentication attempts and track potential security issues.

#### Get Authentication Statistics

**Endpoint:** `GET /admin/v1/auth/stats`

Get statistics about authentication attempts.

**Query Parameters:**
- `window=24h` - Time window (e.g., "1h", "30m", "24h")

**Response:** `200 OK`
```json
{
  "stats": {
    "total_attempts": 1523,
    "successful_attempts": 1489,
    "failed_attempts": 34,
    "unique_ips": 245,
    "unique_usernames": 180,
    "unique_protocols": 3,
    "window_duration": "24h0m0s"
  },
  "window": "24h",
  "window_seconds": 86400
}
```

### Health Monitoring

Monitor system health across components and instances.

#### Get System Health Overview

**Endpoint:** `GET /admin/v1/health/overview`

Get overall system health status.

**Query Parameters:**
- `hostname=mail-server-01` - Filter by specific server

**Response:** `200 OK`
```json
{
  "overall_status": "healthy",
  "component_count": 8,
  "healthy_count": 8,
  "degraded_count": 0,
  "unhealthy_count": 0,
  "unreachable_count": 0,
  "last_updated": "2024-01-20T10:20:00Z"
}
```

#### Get Server Health Status

**Endpoint:** `GET /admin/v1/health/servers/{hostname}`

Get health status for all components on a specific server.

**Response:** `200 OK`
```json
{
  "hostname": "mail-server-01",
  "statuses": [
    {
      "component_name": "database_write",
      "status": "healthy",
      "last_check": "2024-01-20T10:20:00Z",
      "last_error": null,
      "check_count": 1523,
      "fail_count": 0,
      "metadata": {
        "latency_ms": 5,
        "pool_status": "OK"
      },
      "server_hostname": "mail-server-01",
      "updated_at": "2024-01-20T10:20:00Z"
    }
  ],
  "count": 8
}
```

#### Get Component Health Status

**Endpoint:** `GET /admin/v1/health/servers/{hostname}/components/{component}`

Get current or historical health status for a specific component.

**Query Parameters:**
- `history=true` - Return historical data instead of current
- `since=2024-01-20T00:00:00Z` - Start time for history
- `limit=100` - Maximum records to return

**Response (Current):** `200 OK`
```json
{
  "component_name": "database_write",
  "status": "healthy",
  "last_check": "2024-01-20T10:20:00Z",
  "last_error": null,
  "check_count": 1523,
  "fail_count": 0,
  "metadata": {
    "latency_ms": 5
  }
}
```

**Response (History):** `200 OK`
```json
{
  "hostname": "mail-server-01",
  "component": "database_write",
  "history": [...],
  "count": 48,
  "since": "2024-01-20T00:00:00Z"
}
```

### System Configuration

Get API configuration and available endpoints.

#### Get API Configuration

**Endpoint:** `GET /admin/v1/config`

Get API version, features, and available endpoints.

**Response:** `200 OK`
```json
{
  "api_version": "v1",
  "server_type": "admin",
  "features_enabled": {
    "cache": true,
    "health_monitoring": true,
    "mail_delivery": true
  },
  "endpoints": {
    "accounts": ["GET", "POST", "PUT", "DELETE"],
    "connections": ["GET"],
    "cache": ["GET", "POST"],
    "health": ["GET"],
    "mail": ["POST"]
  }
}
```

### Mail Delivery

Deliver mail programmatically via HTTP as an alternative to LMTP.

#### Deliver Mail

**Endpoint:** `POST /admin/v1/mail/deliver`

Deliver an RFC822 message to one or more recipients. Supports Sieve filtering.

**Request Body:**
```json
{
  "recipients": ["user1@example.com", "user2@example.com"],
  "message": "From: sender@example.com\nTo: user1@example.com\nSubject: Test\n\nMessage body"
}
```

**Response (Success):** `200 OK`
```json
{
  "success": true,
  "recipients": [
    {
      "email": "user1@example.com",
      "accepted": true
    },
    {
      "email": "user2@example.com",
      "accepted": true
    }
  ],
  "message_id": "<12345.67890@sora-http-delivery>"
}
```

**Response (Partial Failure):** `207 Multi-Status`
```json
{
  "success": false,
  "recipients": [
    {
      "email": "user1@example.com",
      "accepted": true
    },
    {
      "email": "nonexistent@example.com",
      "accepted": false,
      "error": "Account not found"
    }
  ],
  "message_id": "<12345.67890@sora-http-delivery>",
  "error": "Partial delivery failure"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/admin/v1/mail/deliver \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "recipients": ["user@example.com"],
    "message": "From: sender@example.com\nTo: user@example.com\nSubject: Hello\n\nThis is a test message."
  }'
```

**Notes:**
- Messages must be valid RFC822 format
- Sieve filters are applied to delivered messages
- Large messages (up to server limits) are supported
- Supports MIME multipart messages

### Message Restoration

Restore soft-deleted messages within the grace period.

#### List Deleted Messages

**Endpoint:** `GET /admin/v1/accounts/{email}/messages/deleted`

List messages that have been soft-deleted and can be restored.

**Query Parameters:**
- `mailbox=INBOX` - Filter by mailbox
- `since=2024-01-01T00:00:00Z` - Messages deleted after this time
- `until=2024-01-31T23:59:59Z` - Messages deleted before this time
- `limit=100` - Maximum messages to return

**Response:** `200 OK`
```json
{
  "messages": [
    {
      "id": 12345,
      "uid": 42,
      "content_hash": "blake3_abc123...",
      "mailbox_path": "INBOX",
      "mailbox_id": 5,
      "subject": "Important Email",
      "message_id": "<abc@example.com>",
      "internal_date": "2024-01-15T10:30:00Z",
      "expunged_at": "2024-01-20T14:00:00Z",
      "size": 4096
    }
  ],
  "total": 1
}
```

#### Restore Deleted Messages

**Endpoint:** `POST /admin/v1/accounts/{email}/messages/restore`

Restore deleted messages by ID or criteria.

**Request Body (By IDs):**
```json
{
  "message_ids": [12345, 12346, 12347]
}
```

**Request Body (By Criteria):**
```json
{
  "mailbox": "INBOX",
  "since": "2024-01-01T00:00:00Z",
  "until": "2024-01-31T23:59:59Z"
}
```

**Response:** `200 OK`
```json
{
  "restored": 3,
  "message": "Successfully restored 3 messages"
}
```

## Error Handling

The Admin API uses standard HTTP status codes and returns JSON error responses.

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 207 | Multi-Status | Partial success (e.g., partial mail delivery) |
| 400 | Bad Request | Invalid request parameters or body |
| 401 | Unauthorized | Missing or invalid API key |
| 403 | Forbidden | Operation not allowed |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Error Response Format

All errors return a JSON object with an `error` field:

```json
{
  "error": "Description of what went wrong"
}
```

### Common Errors

**Invalid API Key:**
```json
{
  "error": "Unauthorized"
}
```

**Resource Not Found:**
```json
{
  "error": "Account not found"
}
```

**Validation Error:**
```json
{
  "error": "Email is required"
}
```

**Conflict:**
```json
{
  "error": "Account already exists"
}
```

## Examples

### Complete Account Lifecycle

```bash
# 1. Create account
curl -X POST http://localhost:8080/admin/v1/accounts \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

# 2. Add an alias
curl -X POST http://localhost:8080/admin/v1/accounts/john@example.com/credentials \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "j.doe@example.com",
    "password": "AliasPass456!"
  }'

# 3. Get account details
curl http://localhost:8080/admin/v1/accounts/john@example.com \
  -H "Authorization: Bearer your-api-key"

# 4. Update password
curl -X PUT http://localhost:8080/admin/v1/accounts/john@example.com \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewSecurePass789!"
  }'

# 5. Soft delete account
curl -X DELETE http://localhost:8080/admin/v1/accounts/john@example.com \
  -H "Authorization: Bearer your-api-key"

# 6. Restore account (within grace period)
curl -X POST http://localhost:8080/admin/v1/accounts/john@example.com/restore \
  -H "Authorization: Bearer your-api-key"
```

### Monitoring System Health

```bash
# Get overall health
curl http://localhost:8080/admin/v1/health/overview \
  -H "Authorization: Bearer your-api-key"

# Get server-specific health
curl http://localhost:8080/admin/v1/health/servers/mail-server-01 \
  -H "Authorization: Bearer your-api-key"

# Get component health history
curl "http://localhost:8080/admin/v1/health/servers/mail-server-01/components/database_write?history=true&limit=50" \
  -H "Authorization: Bearer your-api-key"

# Get cache statistics
curl http://localhost:8080/admin/v1/cache/stats \
  -H "Authorization: Bearer your-api-key"

# Get uploader status
curl "http://localhost:8080/admin/v1/uploader/status?show_failed=true" \
  -H "Authorization: Bearer your-api-key"
```

### Connection Management

```bash
# List all connections
curl http://localhost:8080/admin/v1/connections \
  -H "Authorization: Bearer your-api-key"

# Get connection statistics
curl http://localhost:8080/admin/v1/connections/stats \
  -H "Authorization: Bearer your-api-key"

# Get user connections
curl http://localhost:8080/admin/v1/connections/user/john@example.com \
  -H "Authorization: Bearer your-api-key"

# Kick user connections
curl -X POST http://localhost:8080/admin/v1/connections/kick \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "john@example.com"
  }'
```

### Programmatic Mail Delivery

```bash
# Deliver a simple message
curl -X POST http://localhost:8080/admin/v1/mail/deliver \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "recipients": ["user@example.com"],
    "message": "From: system@example.com\nTo: user@example.com\nSubject: Welcome!\n\nWelcome to Sora Mail Server!"
  }'

# Deliver to multiple recipients
curl -X POST http://localhost:8080/admin/v1/mail/deliver \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "recipients": ["user1@example.com", "user2@example.com"],
    "message": "From: admin@example.com\nTo: users@example.com\nSubject: Maintenance Notice\n\nScheduled maintenance tonight at 10 PM."
  }'
```

## Rate Limiting

The Admin API implements rate limiting based on authentication attempts and API key usage:

- **Per IP Rate Limit**: Configurable limit on requests per IP address
- **Authentication Attempts**: Progressive delays on failed authentication
- **No Hard Request Limits**: By default, but can be configured via reverse proxy

**Recommended Practice:**
- Implement exponential backoff on client side
- Cache responses where appropriate
- Use bulk operations when available
- Monitor your API usage via logs

## Best Practices

### Security

1. **Always use TLS in production**
   ```toml
   [servers.http_admin_api]
   tls = true
   tls_cert_file = "/path/to/cert.pem"
   tls_key_file = "/path/to/key.pem"
   ```

2. **Restrict access by IP/hostname**
   ```toml
   allowed_hosts = ["admin.example.com", "10.0.1.0/24"]
   ```

3. **Use strong API keys** (32+ characters, cryptographically random)

4. **Rotate API keys periodically**

5. **Monitor authentication statistics** for suspicious activity

### Performance

1. **Use bulk operations** where available
2. **Cache health check responses** (they change infrequently)
3. **Implement client-side caching** for account details
4. **Use query parameters** to limit response sizes

### Reliability

1. **Implement retry logic** with exponential backoff
2. **Handle partial failures** (207 Multi-Status responses)
3. **Monitor health endpoints** for system status
4. **Set appropriate timeouts** on HTTP clients

### Monitoring

1. **Track API usage** via logs
2. **Monitor error rates** by endpoint
3. **Set up alerts** on health status changes
4. **Track cache hit rates** for performance tuning

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:

```
server/adminapi/admin_api_openapi.yaml
```

You can use this specification to:
- Generate client libraries in various languages
- Import into API testing tools (Postman, Insomnia, etc.)
- Generate documentation
- Validate requests/responses

## Support and Resources

- **GitHub Repository**: https://github.com/migadu/sora
- **Integration Tests**: `integration_tests/adminapi/`
- **Configuration Guide**: See `CLAUDE.md`
- **Example Config**: `config.toml.example`

## Version History

- **v1** (Current): Initial Admin API release with full account, connection, cache, health, and delivery management
