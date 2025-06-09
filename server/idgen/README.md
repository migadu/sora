# Hybrid ID Generator

This package provides a custom ID generation solution. The hybrid ID format offers several advantages:

## Format

Each ID is a ~20-character lowercase base32 string (12 bytes) with the following components:

1. **Timestamp** (4 bytes): Seconds since epoch
   - Provides chronological ordering
   - Enables time-based filtering and querying
   - Makes IDs sortable by creation time

2. **Node ID** (3 bytes): Unique identifier for this server instance
   - Automatically generated at startup
   - Ensures uniqueness across distributed systems
   - Falls back to hostname-based ID if random generation fails

3. **Sequence Number** (2 bytes): Atomically incremented counter
   - Ensures uniqueness even for IDs generated in the same second
   - Prevents collisions in high-concurrency scenarios

4. **Random Data** (3 bytes): Cryptographically secure random data
   - Adds entropy to prevent ID guessing/prediction
   - Provides additional collision resistance

## Advantages

- **Sortable**: Unlike UUIDs, these IDs can be sorted chronologically
- **Performance**: Faster generation than UUID v4
- **Uniqueness**: Collision-resistant even in distributed systems
- **Security**: Unpredictable due to random component
- **Debuggability**: Time component makes it easier to track when IDs were created
- **Space Efficiency**: Compact 12-byte representation (~20 characters in base32)
- **Readability**: Base32 encoding is URL-safe and easily human-readable

## Usage

Simply import the package and call `idgen.New()` to generate a new ID:

```go
import "github.com/migadu/sora/server/idgen"

// Generate a new ID - returns a compact base32-encoded ID (recommended)
id := idgen.New()

// For compatibility with UUID implementation
id := idgen.String()  // Alias for New()
```
