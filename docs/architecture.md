# Sora Architecture

Sora is composed of several distinct components that work together to create a scalable and resilient mail system. Understanding this architecture is key to configuring and deploying Sora effectively.

## Data Flow Diagram

The following diagram illustrates the typical flow of data in a Sora deployment.

```
                               +----------------+
                               |      MTA       | (e.g., Postfix)
                               +----------------+
                                       |
                                       | LMTP (Mail Delivery)
                                       v
+-------------------------------------------------------------------------+
| SORA DEPLOYMENT                                                         |
|                                                                         |
|  +----------------+  (1)   +----------------+  (2)   +---------------+  |
|  |   LMTP Server  | -----> |   Uploader     | -----> |      S3       |  |
|  +----------------+        | (Staging Path) |        | Object Storage|  |
|          |                 +----------------+        +---------------+  |
|          | (3)                                              ^          |
|          |                                                  | (5)      |
|          v                                                  |          |
|  +----------------+  (4)   +----------------+        +----------------+ |
|  |  IMAP/POP3     | <----> | PostgreSQL DB  | <----> |  Local Cache   | |
|  |    Servers     |        |  (Metadata)    |        |(Message Bodies)| |
|  +----------------+        +----------------+        +----------------+ |
|          ^                                                             |
|          | IMAP/POP3 (Client Access)                                   |
|          |                                                             |
|  +----------------+                                                     |
|  | Email Client   |                                                     |
|  +----------------+                                                     |
|                                                                         |
+-------------------------------------------------------------------------+
```

1.  **Mail Reception**: An external Mail Transfer Agent (MTA) delivers an incoming email to Sora's **LMTP Server**. The message is immediately written to the **Uploader's** local staging path. This makes the delivery process extremely fast.
2.  **Asynchronous Upload**: The **Uploader** service runs in the background, picks up the message from the staging path, and uploads it to **S3 Object Storage**.
3.  **Metadata Insertion**: Simultaneously, the LMTP server inserts the message's metadata (headers, flags, mailbox info, etc.) into the **PostgreSQL Database**.
4.  **Client Access**: A user's **Email Client** connects to the **IMAP or POP3 Server** to fetch messages. The server queries the **PostgreSQL DB** for message lists and metadata.
5.  **Body Retrieval**: When a message body is requested, Sora first checks the **Local Cache**. If present (a cache hit), it's served immediately. If not (a cache miss), Sora retrieves it from **S3**, serves it to the client, and stores it in the cache for future requests.

## Component Breakdown

### Data Storage

*   **PostgreSQL Database**: The source of truth for all metadata. It stores accounts, credentials, mailboxes, message flags, and full-text search indexes. Sora requires the `pg_trgm` extension for efficient text searching. The system is designed to work with a primary (write) database and multiple read-replicas for scaling read-heavy workloads.
*   **S3-Compatible Object Storage**: The primary backend for storing raw email content (`.eml` files). This allows storage to scale independently of the rest of the system. Sora supports client-side encryption to secure message bodies before they are sent to S3.

#### Advanced Performance Features

To handle the high demands of a modern mail server, Sora's database schema includes several advanced caching and concurrency control mechanisms:

*   **Statistics Caching (`mailbox_stats`)**: To avoid slow `COUNT(*)` and `SUM(size)` queries on the large `messages` table, Sora maintains a `mailbox_stats` table. This table stores pre-calculated counts and sizes for each mailbox. It is updated efficiently by a `FOR EACH ROW` trigger on the `messages` table, making IMAP `SELECT` and `STATUS` commands extremely fast.

*   **Sequence Number Caching (`message_sequences`)**: Calculating IMAP sequence numbers traditionally requires an expensive `ROW_NUMBER()` window function. Sora pre-calculates and caches these in the `message_sequences` table. This cache is maintained by a `FOR EACH STATEMENT` trigger, which rebuilds the sequence numbers for a mailbox after any change, dramatically improving performance for operations on large mailboxes.
 
*   **Concurrency Control (`pg_advisory_xact_lock`)**: To prevent race conditions and deadlocks during concurrent operations (e.g., two clients modifying the same mailbox simultaneously), Sora uses PostgreSQL advisory locks. By acquiring a lock on a specific mailbox ID, functions like `MoveMessages` and the `maintain_message_sequences` trigger ensure that operations are serialized, guaranteeing data consistency in the cache tables.

### Core Services

*   **Local Cache**: A filesystem-based LRU (Least Recently Used) cache that stores frequently and recently accessed message bodies. This dramatically reduces latency and S3 API costs for common operations like opening a recent email.
*   **Uploader**: A background service that manages the asynchronous upload of messages from a local staging directory to S3. This decouples the fast mail-acceptance path (LMTP) from the potentially slower object storage upload process.
*   **Cleanup**: A background worker that performs essential maintenance. It permanently deletes messages that have been in a "deleted" state beyond a configured grace period, and enforces other data retention policies (e.g., for full-text search data or old logs).

### Protocol Servers

Sora exposes its services through several standard email protocols. Each server can be enabled and configured independently.

*   **IMAP (`servers.imap`)**: The primary protocol for modern email clients to access and manage mail.
*   **LMTP (`servers.lmtp`)**: The Local Mail Transfer Protocol is used to receive mail from your upstream MTAs (e.g., Postfix, Exim). It is also where SIEVE filtering is executed.
*   **POP3 (`servers.pop3`)**: A legacy protocol for clients to download email.
*   **ManageSieve (`servers.managesieve`)**: Allows users to upload and manage their server-side SIEVE filter scripts.

### Scaling and High Availability

*   **Proxy Servers (`servers.*_proxy`)**: Sora includes built-in proxy servers for all major protocols. These proxies can load balance connections across multiple backend Sora nodes, enabling horizontal scaling and high-availability setups. They support user-server affinity (sticky sessions) and an advanced database-driven routing mode (`prelookup`).

### Monitoring and Administration

*   **Prometheus Metrics (`servers.metrics`)**: Exposes a `/metrics` endpoint for Prometheus, providing detailed operational metrics for all components.
*   **HTTP API (`servers.http_api`)**: A RESTful API for programmatic server administration, exposing the functionality of the `sora-admin` CLI tool.
*   **`sora-admin` CLI**: A command-line tool for managing accounts, credentials, mailboxes, running migrations, and performing other administrative tasks.
