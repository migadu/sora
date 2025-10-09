# Sora User API Documentation

The Sora User API provides a modern RESTful HTTP interface for accessing email via web and mobile applications. It offers a simpler alternative to traditional IMAP/POP3 protocols with JWT-based authentication and JSON responses.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Base URL](#base-url)
- [API Endpoints](#api-endpoints)
  - [Authentication](#authentication-endpoints)
  - [Mailbox Operations](#mailbox-operations)
  - [Message Operations](#message-operations)
  - [Search](#search)
  - [Sieve Filters](#sieve-filters)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Overview

The User API is designed for:
- **Web Applications**: Build webmail clients with modern frameworks
- **Mobile Apps**: iOS and Android email applications
- **Third-Party Integrations**: Connect email to other services
- **Custom Clients**: Alternative email clients and tools

**Key Features:**
- RESTful design with JSON request/response
- JWT (JSON Web Token) authentication
- Stateless and scalable
- Full mailbox and message management
- Sieve filter support for server-side filtering
- Full-text search capabilities

**Compared to IMAP/POP3:**
- ✅ Simpler authentication (JWT instead of SASL)
- ✅ JSON responses (easier to parse than IMAP literals)
- ✅ RESTful semantics (standard HTTP verbs)
- ✅ Better mobile support (less connection overhead)
- ✅ Built-in search API
- ❌ No real-time IDLE notifications (use polling)
- ❌ No partial fetch of message parts (fetch full body)

## Authentication

The User API uses JWT (JSON Web Tokens) for authentication. Tokens are obtained by logging in with email and password.

### Authentication Flow

```
1. Client → POST /user/v1/auth/login (email + password)
2. Server → Returns JWT token with expiration
3. Client → Includes JWT in Authorization header for all requests
4. Token expires → Client refreshes token or re-authenticates
```

### Login

**Endpoint:** `POST /user/v1/auth/login`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response:** `200 OK`
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-21T10:30:00Z",
  "account_id": 123
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/user/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure-password"
  }'
```

**Error Response:** `401 Unauthorized`
```json
{
  "error": "Invalid credentials"
}
```

### Using the Token

Include the JWT token in the `Authorization` header for all authenticated requests:

```bash
curl http://localhost:8081/user/v1/mailboxes \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Token Refresh

**Endpoint:** `POST /user/v1/auth/refresh`

Exchange a valid (not expired) token for a new one with extended expiration.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:** `200 OK`
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-22T10:30:00Z"
}
```

**Best Practices:**
- Refresh tokens before they expire (e.g., when 75% of TTL elapsed)
- Store tokens securely (e.g., secure storage on mobile, httpOnly cookies on web)
- Handle 401 responses by re-authenticating
- Never log or expose tokens

## Base URL

The default base URL depends on your configuration:

- **Development**: `http://localhost:8081/user/v1`
- **Production**: `https://mail.example.com/user/v1`

All endpoints are prefixed with `/user/v1/`.

## API Endpoints

### Authentication Endpoints

#### Login

**Endpoint:** `POST /user/v1/auth/login`

Authenticate with email and password to receive a JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "secure-password"
}
```

**Response:** `200 OK`
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-01-21T10:30:00Z",
  "account_id": 123
}
```

**Errors:**
- `400 Bad Request` - Missing email or password
- `401 Unauthorized` - Invalid credentials

#### Refresh Token

**Endpoint:** `POST /user/v1/auth/refresh`

Get a new token before the current one expires.

**Request Body:**
```json
{
  "token": "current-token-here"
}
```

**Response:** `200 OK`
```json
{
  "token": "new-token-here",
  "expires_at": "2024-01-22T10:30:00Z"
}
```

**Errors:**
- `401 Unauthorized` - Invalid or expired token

### Mailbox Operations

#### List Mailboxes

**Endpoint:** `GET /user/v1/mailboxes`

List all mailboxes with message counts and metadata.

**Query Parameters:**
- `subscribed=true` - Only return subscribed mailboxes

**Response:** `200 OK`
```json
{
  "mailboxes": [
    {
      "name": "INBOX",
      "path": "INBOX",
      "subscribed": true,
      "total_messages": 142,
      "unseen_messages": 5,
      "uidvalidity": 1234567890,
      "uidnext": 143
    },
    {
      "name": "Sent",
      "path": "Sent",
      "subscribed": true,
      "total_messages": 87,
      "unseen_messages": 0,
      "uidvalidity": 1234567891,
      "uidnext": 88
    }
  ]
}
```

**Example:**
```bash
curl http://localhost:8081/user/v1/mailboxes \
  -H "Authorization: Bearer your-jwt-token"

# Only subscribed mailboxes
curl http://localhost:8081/user/v1/mailboxes?subscribed=true \
  -H "Authorization: Bearer your-jwt-token"
```

#### Create Mailbox

**Endpoint:** `POST /user/v1/mailboxes`

Create a new mailbox.

**Request Body:**
```json
{
  "name": "Archive/2024"
}
```

**Response:** `201 Created`
```json
{
  "message": "Mailbox created successfully",
  "mailbox": "Archive/2024"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/user/v1/mailboxes \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Projects"
  }'
```

**Notes:**
- Use `/` separator for hierarchical mailboxes
- Mailbox names are case-sensitive
- Special characters should be URL-encoded in paths

**Errors:**
- `400 Bad Request` - Invalid mailbox name
- `409 Conflict` - Mailbox already exists

#### Delete Mailbox

**Endpoint:** `DELETE /user/v1/mailboxes/{name}`

Delete a mailbox. **INBOX cannot be deleted.**

**Response:** `200 OK`
```json
{
  "message": "Mailbox deleted successfully"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8081/user/v1/mailboxes/Archive \
  -H "Authorization: Bearer your-jwt-token"

# For hierarchical mailboxes, URL-encode the path
curl -X DELETE http://localhost:8081/user/v1/mailboxes/Archive%2F2024 \
  -H "Authorization: Bearer your-jwt-token"
```

**Errors:**
- `400 Bad Request` - Cannot delete INBOX
- `404 Not Found` - Mailbox does not exist

#### Subscribe to Mailbox

**Endpoint:** `POST /user/v1/mailboxes/{name}/subscribe`

Mark a mailbox as subscribed.

**Response:** `200 OK`
```json
{
  "message": "Subscribed successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/user/v1/mailboxes/Archive/subscribe \
  -H "Authorization: Bearer your-jwt-token"
```

#### Unsubscribe from Mailbox

**Endpoint:** `POST /user/v1/mailboxes/{name}/unsubscribe`

Mark a mailbox as unsubscribed.

**Response:** `200 OK`
```json
{
  "message": "Unsubscribed successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/user/v1/mailboxes/Spam/unsubscribe \
  -H "Authorization: Bearer your-jwt-token"
```

### Message Operations

#### List Messages

**Endpoint:** `GET /user/v1/mailboxes/{name}/messages`

List messages in a mailbox with pagination.

**Query Parameters:**
- `limit=50` - Number of messages to return (default: 50, max: 1000)
- `offset=0` - Number of messages to skip (for pagination)
- `unseen=true` - Only return unseen messages

**Response:** `200 OK`
```json
{
  "messages": [
    {
      "id": 12345,
      "uid": 142,
      "mailbox": "INBOX",
      "subject": "Meeting Tomorrow",
      "from": "boss@example.com",
      "to": "user@example.com",
      "date": "2024-01-20T10:30:00Z",
      "size": 4096,
      "flags": ["Seen"],
      "has_attachments": false
    }
  ],
  "total": 142,
  "offset": 0,
  "limit": 50
}
```

**Example:**
```bash
# First page (messages 1-50)
curl http://localhost:8081/user/v1/mailboxes/INBOX/messages \
  -H "Authorization: Bearer your-jwt-token"

# Second page (messages 51-100)
curl "http://localhost:8081/user/v1/mailboxes/INBOX/messages?limit=50&offset=50" \
  -H "Authorization: Bearer your-jwt-token"

# Only unseen messages
curl "http://localhost:8081/user/v1/mailboxes/INBOX/messages?unseen=true" \
  -H "Authorization: Bearer your-jwt-token"
```

#### Get Message Details

**Endpoint:** `GET /user/v1/messages/{id}`

Get full message details in JSON format.

**Response:** `200 OK`
```json
{
  "id": 12345,
  "uid": 142,
  "mailbox": "INBOX",
  "subject": "Meeting Tomorrow",
  "from": {
    "name": "John Boss",
    "email": "boss@example.com"
  },
  "to": [
    {
      "name": "You",
      "email": "user@example.com"
    }
  ],
  "cc": [],
  "date": "2024-01-20T10:30:00Z",
  "size": 4096,
  "flags": ["Seen"],
  "headers": {
    "message-id": ["<abc123@example.com>"],
    "x-mailer": ["Sora Mail"]
  },
  "body_text": "Let's meet tomorrow at 2pm.",
  "body_html": "<p>Let's meet tomorrow at 2pm.</p>",
  "attachments": []
}
```

**Example:**
```bash
curl http://localhost:8081/user/v1/messages/12345 \
  -H "Authorization: Bearer your-jwt-token"
```

#### Get Message Body

**Endpoint:** `GET /user/v1/messages/{id}/body`

Get message body in HTML or text format.

**Query Parameters:**
- `format=html` - Return HTML body (default)
- `format=text` - Return plain text body

**Response:** `200 OK`
```
Content-Type: text/html

<p>Let's meet tomorrow at 2pm.</p>
```

**Example:**
```bash
# Get HTML body
curl http://localhost:8081/user/v1/messages/12345/body?format=html \
  -H "Authorization: Bearer your-jwt-token"

# Get plain text body
curl http://localhost:8081/user/v1/messages/12345/body?format=text \
  -H "Authorization: Bearer your-jwt-token"
```

#### Get Raw Message

**Endpoint:** `GET /user/v1/messages/{id}/raw`

Get raw RFC822 message source.

**Response:** `200 OK`
```
Content-Type: message/rfc822

From: boss@example.com
To: user@example.com
Subject: Meeting Tomorrow
Date: Sat, 20 Jan 2024 10:30:00 +0000
Message-ID: <abc123@example.com>

Let's meet tomorrow at 2pm.
```

**Example:**
```bash
curl http://localhost:8081/user/v1/messages/12345/raw \
  -H "Authorization: Bearer your-jwt-token"
```

**Use Cases:**
- Export messages
- Backup messages
- Forward to other systems
- MIME parsing

#### Update Message Flags

**Endpoint:** `PATCH /user/v1/messages/{id}`

Add or remove flags from a message.

**Request Body:**
```json
{
  "add_flags": ["Seen", "Flagged"],
  "remove_flags": ["Draft"]
}
```

**Standard IMAP Flags:**
- `Seen` - Message has been read
- `Answered` - Message has been replied to
- `Flagged` - Message is flagged/starred
- `Deleted` - Message is marked for deletion
- `Draft` - Message is a draft

**Response:** `200 OK`
```json
{
  "message": "Flags updated successfully"
}
```

**Example:**
```bash
# Mark as read and flagged
curl -X PATCH http://localhost:8081/user/v1/messages/12345 \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "add_flags": ["Seen", "Flagged"]
  }'

# Remove draft flag
curl -X PATCH http://localhost:8081/user/v1/messages/12345 \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "remove_flags": ["Draft"]
  }'
```

#### Delete Message

**Endpoint:** `DELETE /user/v1/messages/{id}`

Delete a message (mark as deleted and expunge).

**Response:** `200 OK`
```json
{
  "message": "Message deleted successfully"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8081/user/v1/messages/12345 \
  -H "Authorization: Bearer your-jwt-token"
```

**Note:** Messages are soft-deleted and can be restored within the grace period using the Admin API.

### Search

#### Search Messages

**Endpoint:** `GET /user/v1/mailboxes/{name}/search`

Full-text search messages in a mailbox.

**Query Parameters (all optional):**
- `q=search terms` - Search query (required)
- `from=email@example.com` - Filter by sender
- `subject=keyword` - Filter by subject
- `unseen=true` - Only unseen messages

**Response:** `200 OK`
```json
{
  "messages": [
    {
      "id": 12345,
      "uid": 142,
      "mailbox": "INBOX",
      "subject": "Meeting Tomorrow",
      "from": "boss@example.com",
      "to": "user@example.com",
      "date": "2024-01-20T10:30:00Z",
      "size": 4096,
      "flags": ["Seen"],
      "has_attachments": false
    }
  ],
  "total": 1,
  "query": "meeting"
}
```

**Examples:**
```bash
# Basic text search
curl "http://localhost:8081/user/v1/mailboxes/INBOX/search?q=meeting" \
  -H "Authorization: Bearer your-jwt-token"

# Search with sender filter
curl "http://localhost:8081/user/v1/mailboxes/INBOX/search?q=project&from=boss@example.com" \
  -H "Authorization: Bearer your-jwt-token"

# Search unseen messages only
curl "http://localhost:8081/user/v1/mailboxes/INBOX/search?q=urgent&unseen=true" \
  -H "Authorization: Bearer your-jwt-token"

# Search with subject filter
curl "http://localhost:8081/user/v1/mailboxes/INBOX/search?q=report&subject=quarterly" \
  -H "Authorization: Bearer your-jwt-token"
```

**Search Capabilities:**
- Full-text search using PostgreSQL full-text search
- Searches subject, from, to, and body
- Case-insensitive
- Supports combining filters

### Sieve Filters

Sieve is a mail filtering language for server-side email rules. The User API allows managing Sieve scripts.

#### List Filters

**Endpoint:** `GET /user/v1/filters`

List all Sieve filter scripts.

**Response:** `200 OK`
```json
{
  "filters": [
    {
      "name": "spam-filter",
      "content": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}",
      "active": true,
      "size": 94,
      "created_at": "2024-01-15T10:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z"
    }
  ]
}
```

**Example:**
```bash
curl http://localhost:8081/user/v1/filters \
  -H "Authorization: Bearer your-jwt-token"
```

#### Get Filter

**Endpoint:** `GET /user/v1/filters/{name}`

Get a specific Sieve filter script.

**Response:** `200 OK`
```json
{
  "name": "spam-filter",
  "content": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}",
  "active": true,
  "size": 94,
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z"
}
```

**Example:**
```bash
curl http://localhost:8081/user/v1/filters/spam-filter \
  -H "Authorization: Bearer your-jwt-token"
```

#### Create or Update Filter

**Endpoint:** `PUT /user/v1/filters/{name}`

Create a new filter or update an existing one.

**Request Body:**
```json
{
  "content": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}"
}
```

**Response:** `200 OK` (updated) or `201 Created` (new)
```json
{
  "message": "Filter created successfully"
}
```

**Example:**
```bash
curl -X PUT http://localhost:8081/user/v1/filters/spam-filter \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}"
  }'
```

**Common Sieve Examples:**

**Spam Filter:**
```sieve
require ["fileinto"];
if header :contains "Subject" "[SPAM]" {
  fileinto "Junk";
}
```

**Vacation Auto-Reply:**
```sieve
require ["vacation"];
vacation :days 7 :subject "Out of Office"
"I am currently out of office and will respond when I return.";
```

**Organize by Sender:**
```sieve
require ["fileinto"];
if address :is "from" "boss@example.com" {
  fileinto "Important";
}
```

**Multiple Conditions:**
```sieve
require ["fileinto"];
if allof (
  address :is "from" "newsletter@example.com",
  header :contains "subject" "weekly"
) {
  fileinto "Newsletters/Weekly";
}
```

#### Delete Filter

**Endpoint:** `DELETE /user/v1/filters/{name}`

Delete a Sieve filter script.

**Response:** `200 OK`
```json
{
  "message": "Filter deleted successfully"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:8081/user/v1/filters/old-filter \
  -H "Authorization: Bearer your-jwt-token"
```

#### Activate Filter

**Endpoint:** `POST /user/v1/filters/{name}/activate`

Set a filter script as the active script. Only one script can be active at a time.

**Response:** `200 OK`
```json
{
  "message": "Filter activated successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:8081/user/v1/filters/spam-filter/activate \
  -H "Authorization: Bearer your-jwt-token"
```

#### Get Sieve Capabilities

**Endpoint:** `GET /user/v1/filters/capabilities`

Get supported Sieve extensions and capabilities.

**Response:** `200 OK`
```json
{
  "extensions": [
    "fileinto",
    "vacation",
    "regex",
    "envelope",
    "body",
    "imap4flags"
  ],
  "max_script_size": 65536
}
```

**Example:**
```bash
curl http://localhost:8081/user/v1/filters/capabilities \
  -H "Authorization: Bearer your-jwt-token"
```

## Error Handling

The User API uses standard HTTP status codes and returns JSON error responses.

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request parameters or body |
| 401 | Unauthorized | Missing or invalid JWT token |
| 403 | Forbidden | Operation not allowed (e.g., delete INBOX) |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |

### Error Response Format

All errors return a JSON object with an `error` field:

```json
{
  "error": "Description of what went wrong"
}
```

### Common Errors

**Invalid or Expired Token:**
```json
{
  "error": "Invalid or expired token"
}
```
→ Re-authenticate to get a new token

**Resource Not Found:**
```json
{
  "error": "Mailbox not found"
}
```

**Validation Error:**
```json
{
  "error": "Mailbox name is required"
}
```

**Permission Error:**
```json
{
  "error": "Cannot delete INBOX"
}
```

## Examples

### Building a Webmail Client

**Complete email reading flow:**

```javascript
// 1. Login
const loginResponse = await fetch('http://localhost:8081/user/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password'
  })
});
const { token } = await loginResponse.json();

// 2. List mailboxes
const mailboxesResponse = await fetch('http://localhost:8081/user/v1/mailboxes', {
  headers: { 'Authorization': `Bearer ${token}` }
});
const { mailboxes } = await mailboxesResponse.json();

// 3. Get messages from INBOX
const messagesResponse = await fetch(
  'http://localhost:8081/user/v1/mailboxes/INBOX/messages?limit=50&offset=0',
  { headers: { 'Authorization': `Bearer ${token}` }}
);
const { messages, total } = await messagesResponse.json();

// 4. Read a specific message
const messageResponse = await fetch(
  `http://localhost:8081/user/v1/messages/${messages[0].id}`,
  { headers: { 'Authorization': `Bearer ${token}` }}
);
const message = await messageResponse.json();

// 5. Mark as read
await fetch(`http://localhost:8081/user/v1/messages/${messages[0].id}`, {
  method: 'PATCH',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ add_flags: ['Seen'] })
});
```

### Mobile App Message List

**Efficient message list with pagination:**

```swift
// Swift/iOS example
func fetchMessages(mailbox: String, offset: Int = 0, limit: Int = 50) async throws -> MessageList {
    var request = URLRequest(url: URL(string: "http://localhost:8081/user/v1/mailboxes/\(mailbox)/messages?limit=\(limit)&offset=\(offset)")!)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONDecoder().decode(MessageList.self, from: data)
}

// Load first page
let messages = try await fetchMessages(mailbox: "INBOX")

// Load next page when scrolling
let moreMessages = try await fetchMessages(mailbox: "INBOX", offset: 50)
```

### Search Implementation

```python
# Python example
import requests

def search_messages(token, mailbox, query, from_email=None, unseen_only=False):
    """Search messages with filters"""
    url = f"http://localhost:8081/user/v1/mailboxes/{mailbox}/search"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"q": query}

    if from_email:
        params["from"] = from_email
    if unseen_only:
        params["unseen"] = "true"

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()

# Search for urgent messages from boss
results = search_messages(
    token=jwt_token,
    mailbox="INBOX",
    query="urgent",
    from_email="boss@example.com"
)
print(f"Found {results['total']} messages")
```

### Sieve Filter Management

```bash
#!/bin/bash
TOKEN="your-jwt-token"
BASE_URL="http://localhost:8081/user/v1"

# Create a spam filter
curl -X PUT "$BASE_URL/filters/spam-filter" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[SPAM]\" {\n  fileinto \"Junk\";\n}"
  }'

# Activate the filter
curl -X POST "$BASE_URL/filters/spam-filter/activate" \
  -H "Authorization: Bearer $TOKEN"

# List all filters
curl "$BASE_URL/filters" \
  -H "Authorization: Bearer $TOKEN"
```

### Token Refresh Pattern

```javascript
// JavaScript token refresh helper
class SoraClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.token = null;
    this.tokenExpiry = null;
  }

  async login(email, password) {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    this.token = data.token;
    this.tokenExpiry = new Date(data.expires_at);
    return data;
  }

  async refreshTokenIfNeeded() {
    // Refresh if token expires in less than 15 minutes
    const fifteenMinutes = 15 * 60 * 1000;
    if (this.tokenExpiry && (this.tokenExpiry - Date.now() < fifteenMinutes)) {
      const response = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: this.token })
      });
      const data = await response.json();
      this.token = data.token;
      this.tokenExpiry = new Date(data.expires_at);
    }
  }

  async request(endpoint, options = {}) {
    await this.refreshTokenIfNeeded();
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.token}`
      }
    });

    if (response.status === 401) {
      // Token invalid, need to re-login
      throw new Error('Authentication required');
    }

    return response.json();
  }
}

// Usage
const client = new SoraClient('http://localhost:8081/user/v1');
await client.login('user@example.com', 'password');
const mailboxes = await client.request('/mailboxes');
```

## Best Practices

### Security

1. **Always use HTTPS in production**
   - Tokens are sensitive and should never be transmitted over HTTP
   - Configure TLS in your server settings

2. **Secure token storage**
   - **Web**: Use httpOnly cookies or secure storage APIs
   - **Mobile**: Use Keychain (iOS) or KeyStore (Android)
   - **Never** store in localStorage or visible to JavaScript

3. **Implement token refresh**
   - Refresh tokens before expiration
   - Handle 401 responses gracefully
   - Re-authenticate when refresh fails

4. **Rate limiting**
   - Implement client-side rate limiting
   - Use exponential backoff on errors
   - Cache responses where appropriate

### Performance

1. **Pagination**
   - Always use pagination for message lists
   - Default limit: 50 messages
   - Implement infinite scroll with offset

2. **Caching**
   - Cache mailbox lists (update on changes)
   - Cache message headers (invalidate on new messages)
   - Don't cache message bodies (they're large)

3. **Efficient message loading**
   ```javascript
   // Good: Load only what you need
   const headers = await fetch('/mailboxes/INBOX/messages?limit=50');

   // Bad: Loading all messages
   const all = await fetch('/mailboxes/INBOX/messages?limit=10000');
   ```

4. **Search optimization**
   - Debounce search input (wait 300ms after typing stops)
   - Cancel previous search requests
   - Use specific filters to reduce results

### Reliability

1. **Error handling**
   ```javascript
   async function fetchWithRetry(url, options, maxRetries = 3) {
     for (let i = 0; i < maxRetries; i++) {
       try {
         const response = await fetch(url, options);
         if (response.ok) return response;
         if (response.status === 401) throw new Error('Auth failed');
         // Retry on 5xx errors
         if (response.status >= 500 && i < maxRetries - 1) {
           await sleep(Math.pow(2, i) * 1000); // Exponential backoff
           continue;
         }
         throw new Error(`HTTP ${response.status}`);
       } catch (error) {
         if (i === maxRetries - 1) throw error;
         await sleep(Math.pow(2, i) * 1000);
       }
     }
   }
   ```

2. **Offline support**
   - Implement local caching for read messages
   - Queue operations when offline
   - Sync when connection restored

3. **Connection handling**
   - Set appropriate timeouts (30s for most requests)
   - Handle network errors gracefully
   - Show connection status to users

### Mobile Considerations

1. **Battery optimization**
   - Use polling instead of keeping connections open
   - Poll every 5-15 minutes when app is active
   - Stop polling when app is backgrounded

2. **Bandwidth optimization**
   - Only fetch message bodies when opened
   - Use smaller page sizes (20-30 messages)
   - Compress requests if possible

3. **Background refresh**
   - Use platform background fetch APIs
   - Update unread counts
   - Show notifications for new messages

### Web Application Tips

1. **Progressive loading**
   ```javascript
   // Load mailboxes first
   const mailboxes = await loadMailboxes();

   // Then load INBOX preview
   const inbox = await loadMessages('INBOX', 0, 20);

   // Load full list on demand
   ```

2. **Virtual scrolling**
   - For large message lists
   - Only render visible messages
   - Load more as user scrolls

3. **Optimistic updates**
   ```javascript
   // Update UI immediately
   message.flags.push('Seen');
   updateUI(message);

   // Sync with server
   await api.updateFlags(message.id, { add_flags: ['Seen'] })
     .catch(error => {
       // Revert on failure
       message.flags = message.flags.filter(f => f !== 'Seen');
       updateUI(message);
     });
   ```

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:

```
server/userapi/user_api_openapi.yaml
```

Use this specification to:
- Generate client libraries in various languages
- Import into API testing tools (Postman, Insomnia)
- Generate documentation
- Validate requests/responses

**Example: Generate TypeScript client**
```bash
npx @openapitools/openapi-generator-cli generate \
  -i server/userapi/user_api_openapi.yaml \
  -g typescript-axios \
  -o ./client
```

## Comparison with IMAP/POP3

| Feature | User API | IMAP | POP3 |
|---------|----------|------|------|
| Protocol | HTTP/REST | TCP Binary | TCP Binary |
| Auth | JWT | SASL/Plain | Plain |
| Response Format | JSON | IMAP Literals | Text |
| Mailbox Management | ✅ Full | ✅ Full | ❌ No |
| Search | ✅ Full-text | ✅ SEARCH | ❌ No |
| Filtering | ✅ Sieve API | ❌ Client-side | ❌ No |
| Real-time Updates | ❌ Poll | ✅ IDLE | ❌ Poll |
| Partial Fetch | ❌ Full only | ✅ BODYPART | ✅ TOP |
| Mobile Friendly | ✅✅ | ✅ | ✅ |
| Web Friendly | ✅✅ | ❌ | ❌ |
| Complexity | Low | High | Medium |

**When to use User API:**
- ✅ Building web applications
- ✅ Building mobile apps
- ✅ Need JSON responses
- ✅ Want simpler authentication
- ✅ Need built-in search

**When to use IMAP:**
- ✅ Need real-time push notifications (IDLE)
- ✅ Need partial message fetching
- ✅ Building desktop email clients
- ✅ Need maximum compatibility

## Support and Resources

- **GitHub Repository**: https://github.com/migadu/sora
- **Integration Tests**: `integration_tests/httpuserapi/`
- **OpenAPI Spec**: `server/userapi/user_api_openapi.yaml`
- **Configuration Guide**: See `CLAUDE.md`
- **Example Config**: `config.toml.example`

## Version History

- **v1** (Current): Initial User API release with full mailbox, message, search, and Sieve filter management
