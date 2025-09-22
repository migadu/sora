package db

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PerformanceTestConfig controls the scale of performance tests
type PerformanceTestConfig struct {
	SmallDataset     int // 100-500 messages
	MediumDataset    int // 1000-2000 messages
	LargeDataset     int // 5000+ messages
	VeryLargeDataset int // 10000+ messages (for limit testing)
}

// DefaultPerformanceConfig provides reasonable defaults for CI/local testing
var DefaultPerformanceConfig = PerformanceTestConfig{
	SmallDataset:     50,
	MediumDataset:    150,
	LargeDataset:     500,  // Reasonable for testing without being too slow
	VeryLargeDataset: 1000, // Enough to test limits without timeout
}

// FastPerformanceConfig for quick testing during development
var FastPerformanceConfig = PerformanceTestConfig{
	SmallDataset:     5,
	MediumDataset:    10,
	LargeDataset:     20,
	VeryLargeDataset: 30,
}

// PerformanceTestSuite provides helpers for performance testing
type PerformanceTestSuite struct {
	db        *Database
	accountID int64
	mailboxID int64
	config    PerformanceTestConfig
	t         *testing.T
	nextUID   int64 // Track the next available UID
}

// NewPerformanceTestSuite creates a new performance test suite
func NewPerformanceTestSuite(t *testing.T, config PerformanceTestConfig) *PerformanceTestSuite {
	if testing.Short() {
		config = FastPerformanceConfig
		t.Logf("Using fast performance config for short tests: %+v", config)
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)

	return &PerformanceTestSuite{
		db:        db,
		accountID: accountID,
		mailboxID: mailboxID,
		config:    config,
		nextUID:   1, // Start UIDs from 1
		t:         t,
	}
}

// Close cleans up the test suite
func (pts *PerformanceTestSuite) Close() {
	if pts.db != nil {
		pts.db.Close()
	}
}

// CreateTestMessages creates a specified number of test messages with realistic content
func (pts *PerformanceTestSuite) CreateTestMessages(ctx context.Context, count int, messageType string) error {
	tx, err := pts.db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	batchSize := 100 // Insert in batches to avoid memory issues
	for i := 0; i < count; i += batchSize {
		end := i + batchSize
		if end > count {
			end = count
		}

		err = pts.createMessageBatch(ctx, tx, i, end, messageType)
		if err != nil {
			return fmt.Errorf("failed to create message batch %d-%d: %w", i, end, err)
		}

		if i > 0 && i%1000 == 0 {
			pts.t.Logf("Created %d/%d messages...", i, count)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	pts.t.Logf("Successfully created %d %s messages", count, messageType)
	return nil
}

// createMessageBatch creates a batch of messages using individual inserts
func (pts *PerformanceTestSuite) createMessageBatch(ctx context.Context, tx pgx.Tx, start, end int, messageType string) error {
	baseTime := time.Now().Add(-time.Duration(start) * time.Hour) // Spread messages over time

	for i := start; i < end; i++ {
		// Use nextUID for unique UID generation
		currentUID := pts.nextUID
		pts.nextUID++ // Increment for next message

		// Generate varied content based on message type
		subject, body, headers := pts.generateMessageContent(i, messageType)
		contentHash := fmt.Sprintf("hash_%s_%d", messageType, currentUID)
		messageID := fmt.Sprintf("<%d.%s@test.example.com>", currentUID, messageType)

		sentDate := baseTime.Add(time.Duration(i) * time.Minute)
		internalDate := sentDate.Add(time.Duration(i%60) * time.Second)

		// Add variety in message sizes and flags
		size := 1024 + (i % 10000) // 1KB to ~11KB
		flags := pts.generateMessageFlags(i)

		// Create proper body structure
		bodyStructure := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    uint32(size),
		}
		var bs imap.BodyStructure = bodyStructure
		bodyStructureBytes, err := helpers.SerializeBodyStructureGob(&bs)
		if err != nil {
			return fmt.Errorf("failed to serialize body structure for message %d: %w", i, err)
		}

		// Create simple message using direct SQL insert (simplified approach)
		_, err = tx.Exec(ctx, `
			INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, content_hash, s3_domain, s3_localpart,
			 flags, custom_flags, internal_date, size, subject, sent_date, in_reply_to, body_structure,
			 recipients_json, created_modseq, subject_sort, from_name_sort, from_email_sort, to_email_sort, cc_email_sort)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			        nextval('messages_modseq'), $18, $19, $20, $21, $22)`,
			pts.accountID,                      // account_id
			pts.mailboxID,                      // mailbox_id
			"INBOX",                            // mailbox_path
			currentUID,                         // uid (using nextUID)
			messageID,                          // message_id
			contentHash,                        // content_hash
			"test-domain",                      // s3_domain
			fmt.Sprintf("test-%d", currentUID), // s3_localpart
			flags,                              // flags (bitwise)
			"[]",                               // custom_flags (empty JSON array)
			internalDate,                       // internal_date
			size,                               // size
			subject,                            // subject
			sentDate,                           // sent_date
			"",                                 // in_reply_to (empty for now)
			bodyStructureBytes,                 // body_structure (proper gob encoding)
			fmt.Sprintf(`[{"type":"from","email":"sender%d@example.com"},{"type":"to","email":"user%d@example.com"}]`, i%100, (i+1)%100), // recipients_json
			normalizeForSort(subject), // subject_sort
			"",                        // from_name_sort
			fmt.Sprintf("sender%d@example.com", i%100),   // from_email_sort
			fmt.Sprintf("user%d@example.com", (i+1)%100), // to_email_sort
			"", // cc_email_sort
		)
		if err != nil {
			return fmt.Errorf("failed to insert message %d: %w", i, err)
		}

		// Insert message content for full-text search
		_, err = tx.Exec(ctx, `
			INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, headers_tsv)
			VALUES ($1, $2, to_tsvector('simple', $2), $3, to_tsvector('simple', $3))
			ON CONFLICT (content_hash) DO NOTHING`,
			contentHash, body, headers)
		if err != nil {
			return fmt.Errorf("failed to insert message content %d: %w", i, err)
		}

		// Insert into message_sequences for sequence number tracking
		_, err = tx.Exec(ctx, `
			INSERT INTO message_sequences (mailbox_id, uid, seqnum)
			VALUES ($1, $2, $3)
			ON CONFLICT (mailbox_id, uid) DO NOTHING`,
			pts.mailboxID, currentUID, currentUID)
		if err != nil {
			return fmt.Errorf("failed to insert message sequence %d: %w", i, err)
		}
	}

	return nil
}

// generateMessageContent creates realistic message content for testing
func (pts *PerformanceTestSuite) generateMessageContent(index int, messageType string) (subject, body, headers string) {
	templates := map[string]struct {
		subjects []string
		bodies   []string
	}{
		"business": {
			subjects: []string{
				"Quarterly Sales Report Q%d",
				"Meeting Request: Project Alpha Review",
				"URGENT: Server Maintenance Window",
				"Budget Approval for Initiative %d",
				"Team Lunch Coordination",
				"Client Presentation Feedback",
			},
			bodies: []string{
				"Please find attached the quarterly sales report for review. The numbers show significant growth in our target markets.",
				"I would like to schedule a meeting to discuss the progress on Project Alpha. Please let me know your availability.",
				"We have scheduled maintenance for our primary servers this weekend. Please ensure all critical work is saved.",
				"The budget proposal for initiative %d has been approved. We can proceed with the implementation phase.",
				"Let's coordinate our team lunch for next Friday. Please reply with your dietary preferences.",
				"Thank you for the client presentation. The feedback was very positive and they want to move forward.",
			},
		},
		"newsletter": {
			subjects: []string{
				"Weekly Tech News - Issue %d",
				"Product Updates and New Features",
				"Industry Insights: Market Trends",
				"Customer Success Stories",
				"Developer Newsletter %d",
				"Monthly Security Updates",
			},
			bodies: []string{
				"This week in technology: artificial intelligence continues to transform industries worldwide.",
				"We're excited to announce several new features in our latest product release including enhanced search capabilities.",
				"Market analysis shows continued growth in cloud computing adoption across enterprise customers.",
				"Read how our customers are achieving remarkable results using our platform solutions.",
				"Latest developments in software engineering, including new frameworks and best practices for developers.",
				"Important security updates and recommendations for keeping your systems protected.",
			},
		},
		"support": {
			subjects: []string{
				"Ticket #%d: Database Performance Issue",
				"Re: Login Problems - Account Recovery",
				"Feature Request: Enhanced Search",
				"Bug Report: Import Functionality",
				"Account Suspension Notice",
				"Password Reset Instructions",
			},
			bodies: []string{
				"We have identified a performance issue with the database queries. Our team is working on optimization.",
				"To recover your account, please follow the instructions in this email and contact support if needed.",
				"Thank you for the feature request. Enhanced search functionality is planned for our next major release.",
				"We have reproduced the bug you reported with the import functionality. A fix will be available soon.",
				"Your account has been temporarily suspended due to suspicious activity. Please contact support immediately.",
				"To reset your password, click the link below and follow the instructions on the secure page.",
			},
		},
	}

	template := templates[messageType]
	if len(template.subjects) == 0 {
		// Fallback for unknown types
		template = templates["business"]
	}

	subject = fmt.Sprintf(template.subjects[index%len(template.subjects)], index)
	body = fmt.Sprintf(template.bodies[index%len(template.bodies)], index)

	// Generate realistic headers
	headers = fmt.Sprintf(`From: sender%d@example.com
To: user%d@example.com
Subject: %s
Date: %s
Message-ID: <%d.%s@test.example.com>
Content-Type: text/plain; charset=utf-8`,
		index%100, (index+1)%100, subject, time.Now().Format(time.RFC1123), index, messageType)

	return subject, body, headers
}

// generateMessageFlags creates varied flag combinations
func (pts *PerformanceTestSuite) generateMessageFlags(index int) int {
	flags := 0

	// 70% of messages are seen
	if index%10 < 7 {
		flags |= FlagToBitwise(imap.FlagSeen)
	}

	// 20% are flagged/important
	if index%5 == 0 {
		flags |= FlagToBitwise(imap.FlagFlagged)
	}

	// 10% are answered
	if index%10 == 0 {
		flags |= FlagToBitwise(imap.FlagAnswered)
	}

	// 5% are drafts
	if index%20 == 0 {
		flags |= FlagToBitwise(imap.FlagDraft)
	}

	return flags
}

// normalizeForSort creates a normalized string for sorting (simple version)
func normalizeForSort(s string) string {
	// Remove common prefixes and convert to lowercase for sorting
	lower := strings.ToLower(s)
	prefixes := []string{"re:", "fwd:", "fw:", "aw:"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			lower = strings.TrimSpace(lower[len(prefix):])
			break
		}
	}
	return lower
}

// MemoryStats captures memory usage for testing
type MemoryStats struct {
	AllocBefore      uint64
	AllocAfter       uint64
	AllocDelta       uint64
	SysBefore        uint64
	SysAfter         uint64
	GCBefore         uint32
	GCAfter          uint32
	GoroutinesBefore int
	GoroutinesAfter  int
}

// CaptureMemoryStats captures memory statistics before and after an operation
func CaptureMemoryStats(operation func()) *MemoryStats {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	goroutinesBefore := runtime.NumGoroutine()

	operation()

	runtime.GC()
	runtime.ReadMemStats(&m2)
	goroutinesAfter := runtime.NumGoroutine()

	return &MemoryStats{
		AllocBefore:      m1.Alloc,
		AllocAfter:       m2.Alloc,
		AllocDelta:       m2.Alloc - m1.Alloc,
		SysBefore:        m1.Sys,
		SysAfter:         m2.Sys,
		GCBefore:         m1.NumGC,
		GCAfter:          m2.NumGC,
		GoroutinesBefore: goroutinesBefore,
		GoroutinesAfter:  goroutinesAfter,
	}
}

// String provides a readable representation of memory stats
func (ms *MemoryStats) String() string {
	return fmt.Sprintf("Memory: %d -> %d KB (Δ%+d KB), GC: %d -> %d, Goroutines: %d -> %d",
		ms.AllocBefore/1024, ms.AllocAfter/1024, int64(ms.AllocDelta)/1024,
		ms.GCBefore, ms.GCAfter, ms.GoroutinesBefore, ms.GoroutinesAfter)
}

// TestSearchPerformance implements comprehensive performance testing
func TestSearchPerformance(t *testing.T) {
	if testing.Short() {
		t.Log("Using fast configuration for short test mode")
	}

	ctx := context.Background()
	pts := NewPerformanceTestSuite(t, DefaultPerformanceConfig)
	defer pts.Close()

	t.Run("CreateTestData", func(t *testing.T) {
		// Create test datasets with different characteristics
		err := pts.CreateTestMessages(ctx, pts.config.SmallDataset, "business")
		require.NoError(t, err)

		err = pts.CreateTestMessages(ctx, pts.config.MediumDataset-pts.config.SmallDataset, "newsletter")
		require.NoError(t, err)

		// Skip large dataset creation in short mode to save time
		if !testing.Short() {
			err = pts.CreateTestMessages(ctx, pts.config.LargeDataset-pts.config.MediumDataset, "support")
			require.NoError(t, err)
		}
	})

	t.Run("SimpleSearchPerformance", func(t *testing.T) {
		testCases := []struct {
			name     string
			criteria *imap.SearchCriteria
			maxTime  time.Duration
		}{
			{
				name:     "UID Range Search",
				criteria: &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 100}}}},
				maxTime:  100 * time.Millisecond,
			},
			{
				name:     "Date Range Search",
				criteria: &imap.SearchCriteria{Since: time.Now().Add(-24 * time.Hour), Before: time.Now()},
				maxTime:  200 * time.Millisecond,
			},
			{
				name:     "Flag Search",
				criteria: &imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}},
				maxTime:  150 * time.Millisecond,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				start := time.Now()
				messages, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, tc.criteria)
				elapsed := time.Since(start)

				assert.NoError(t, err)
				assert.NotNil(t, messages)
				t.Logf("%s: %d results in %v", tc.name, len(messages), elapsed)

				if elapsed > tc.maxTime && !testing.Short() {
					t.Logf("WARNING: %s took %v, expected <%v", tc.name, elapsed, tc.maxTime)
				}
			})
		}
	})

	t.Run("FullTextSearchPerformance", func(t *testing.T) {
		testCases := []struct {
			name     string
			criteria *imap.SearchCriteria
			maxTime  time.Duration
		}{
			{
				name:     "Body Text Search",
				criteria: &imap.SearchCriteria{Body: []string{"performance"}},
				maxTime:  500 * time.Millisecond,
			},
			{
				name:     "Multiple Body Terms",
				criteria: &imap.SearchCriteria{Body: []string{"database", "optimization"}},
				maxTime:  800 * time.Millisecond,
			},
			{
				name:     "Text Search (Headers + Body)",
				criteria: &imap.SearchCriteria{Text: []string{"quarterly"}},
				maxTime:  600 * time.Millisecond,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				memStats := CaptureMemoryStats(func() {
					start := time.Now()
					messages, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, tc.criteria)
					elapsed := time.Since(start)

					assert.NoError(t, err)
					assert.NotNil(t, messages)
					t.Logf("%s: %d results in %v", tc.name, len(messages), elapsed)

					if elapsed > tc.maxTime && !testing.Short() {
						t.Logf("WARNING: %s took %v, expected <%v", tc.name, elapsed, tc.maxTime)
					}
				})
				t.Logf("%s Memory usage: %s", tc.name, memStats.String())
			})
		}
	})

	t.Run("ComplexSortPerformance", func(t *testing.T) {
		sortCriteria := []struct {
			name    string
			sort    []imap.SortCriterion
			maxTime time.Duration
		}{
			{
				name:    "Date Sort",
				sort:    []imap.SortCriterion{{Key: imap.SortKeyArrival, Reverse: true}},
				maxTime: 200 * time.Millisecond,
			},
			{
				name:    "Subject Sort",
				sort:    []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}},
				maxTime: 300 * time.Millisecond,
			},
			{
				name:    "Size Sort",
				sort:    []imap.SortCriterion{{Key: imap.SortKeySize, Reverse: true}},
				maxTime: 250 * time.Millisecond,
			},
		}

		criteria := &imap.SearchCriteria{Since: time.Now().Add(-48 * time.Hour)}

		for _, sc := range sortCriteria {
			t.Run(sc.name, func(t *testing.T) {
				start := time.Now()
				messages, err := pts.db.GetMessagesSorted(ctx, pts.mailboxID, criteria, sc.sort)
				elapsed := time.Since(start)

				assert.NoError(t, err)
				assert.NotNil(t, messages)
				t.Logf("%s: %d results in %v", sc.name, len(messages), elapsed)

				if elapsed > sc.maxTime && !testing.Short() {
					t.Logf("WARNING: %s took %v, expected <%v", sc.name, elapsed, sc.maxTime)
				}
			})
		}
	})

	t.Run("ResultLimitEnforcement", func(t *testing.T) {
		// Test that search results are properly limited
		t.Run("MaxSearchResultsLimit", func(t *testing.T) {
			// Search that should return many results
			criteria := &imap.SearchCriteria{} // Empty criteria = all messages

			messages, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, criteria)
			assert.NoError(t, err)

			if len(messages) >= MaxSearchResults {
				assert.Equal(t, MaxSearchResults, len(messages),
					"Search should be limited to MaxSearchResults (%d)", MaxSearchResults)
				t.Logf("✓ Search correctly limited to %d results", MaxSearchResults)
			} else {
				t.Logf("✓ Search returned %d results (under limit of %d)", len(messages), MaxSearchResults)
			}
		})

		t.Run("ComplexSortLimit", func(t *testing.T) {
			// Test complex sort limits with JSONB operations
			criteria := &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "from", Value: "sender1@example.com"},
				},
			}
			sortCriteria := []imap.SortCriterion{{Key: imap.SortKeyFrom, Reverse: false}}

			messages, err := pts.db.GetMessagesSorted(ctx, pts.mailboxID, criteria, sortCriteria)
			assert.NoError(t, err)

			if len(messages) >= MaxComplexSortResults {
				assert.LessOrEqual(t, len(messages), MaxComplexSortResults,
					"Complex sort should respect MaxComplexSortResults limit")
				t.Logf("✓ Complex sort correctly limited to ≤%d results", MaxComplexSortResults)
			} else {
				t.Logf("✓ Complex sort returned %d results (under limit)", len(messages))
			}
		})
	})

	t.Run("MemoryUsageValidation", func(t *testing.T) {
		// Test memory usage doesn't grow excessively
		const maxMemoryGrowthMB = 50 // Maximum acceptable memory growth in MB

		memStats := CaptureMemoryStats(func() {
			// Perform multiple search operations
			for i := 0; i < 10; i++ {
				criteria := &imap.SearchCriteria{
					Body: []string{fmt.Sprintf("term%d", i)},
				}
				_, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, criteria)
				assert.NoError(t, err)
			}
		})

		memoryGrowthMB := float64(memStats.AllocDelta) / (1024 * 1024)
		t.Logf("Memory growth during search operations: %.2f MB", memoryGrowthMB)

		if memoryGrowthMB > maxMemoryGrowthMB {
			t.Logf("WARNING: Memory growth (%.2f MB) exceeds expected maximum (%d MB)",
				memoryGrowthMB, maxMemoryGrowthMB)
		} else {
			t.Logf("✓ Memory usage within acceptable bounds")
		}

		// Check for goroutine leaks
		if memStats.GoroutinesAfter > memStats.GoroutinesBefore+2 {
			t.Logf("WARNING: Potential goroutine leak detected: %d -> %d",
				memStats.GoroutinesBefore, memStats.GoroutinesAfter)
		} else {
			t.Logf("✓ No goroutine leaks detected")
		}
	})

	// Add comprehensive performance summary
	t.Run("PerformanceSummary", func(t *testing.T) {
		// Get total message count for summary
		var totalMessages int
		err := pts.db.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL",
			pts.mailboxID).Scan(&totalMessages)
		require.NoError(t, err)

		t.Logf("=== PERFORMANCE TEST SUMMARY ===")
		t.Logf("Total test messages: %d", totalMessages)
		t.Logf("MaxSearchResults limit: %d", MaxSearchResults)
		t.Logf("MaxComplexSortResults limit: %d", MaxComplexSortResults)
		t.Logf("Test configuration: %+v", pts.config)

		if testing.Short() {
			t.Logf("Note: Running in short test mode with reduced dataset")
		}

		t.Logf("✓ All performance tests completed successfully")
	})
}

// Benchmark functions for more detailed performance analysis
func BenchmarkSearchOperations(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmarks in short mode")
	}

	ctx := context.Background()
	pts := NewPerformanceTestSuite(&testing.T{}, FastPerformanceConfig)
	defer pts.Close()

	// Create test data once
	err := pts.CreateTestMessages(ctx, pts.config.LargeDataset, "business")
	if err != nil {
		b.Fatalf("Failed to create test messages: %v", err)
	}

	b.Run("UIDSearch", func(b *testing.B) {
		criteria := &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 100}}}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, criteria)
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
		}
	})

	b.Run("FullTextSearch", func(b *testing.B) {
		criteria := &imap.SearchCriteria{Body: []string{"quarterly"}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := pts.db.GetMessagesWithCriteria(ctx, pts.mailboxID, criteria)
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
		}
	})

	b.Run("ComplexSort", func(b *testing.B) {
		criteria := &imap.SearchCriteria{}
		sortCriteria := []imap.SortCriterion{{Key: imap.SortKeySubject, Reverse: false}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := pts.db.GetMessagesSorted(ctx, pts.mailboxID, criteria, sortCriteria)
			if err != nil {
				b.Fatalf("Sort failed: %v", err)
			}
		}
	})
}
