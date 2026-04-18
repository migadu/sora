package db

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestBuildSearchCriteria_TextSearch verifies that TEXT searches correctly query
// both FTS indexes and dedicated columns (subject, from/to/cc sort fields).
func TestBuildSearchCriteria_TextSearch(t *testing.T) {
	db := &Database{}

	tests := []struct {
		name              string
		searchText        string
		expectedInQuery   []string // Substrings that must appear in the generated SQL
		unexpectedInQuery []string // Substrings that must NOT appear
	}{
		{
			name:       "TEXT search includes all relevant columns",
			searchText: "alice",
			expectedInQuery: []string{
				"text_body_tsv",             // Body FTS
				"LOWER(m.subject) LIKE",     // Subject column (with table prefix)
				"from_email_sort LIKE",      // From email
				"from_name_sort LIKE",       // From name
				"to_email_sort LIKE",        // To email
				"to_name_sort LIKE",         // To name
				"cc_email_sort LIKE",        // Cc email
				"plainto_tsquery('simple',", // FTS query function
			},
			unexpectedInQuery: []string{
				"recipients_json::text", // Should NOT use JSON text casting (fragile)
				"headers_tsv",           // Should NOT use headers_tsv (removed in migration 000030)
			},
		},
		{
			name:       "TEXT search with email address",
			searchText: "user@example.com",
			expectedInQuery: []string{
				"from_email_sort LIKE",
				"to_email_sort LIKE",
			},
		},
		{
			name:       "TEXT search with partial name",
			searchText: "Smith",
			expectedInQuery: []string{
				"from_name_sort LIKE",
				"to_name_sort LIKE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := &imap.SearchCriteria{
				Text: []string{tt.searchText},
			}

			paramCounter := 0
			query, args, err := db.buildSearchCriteria(criteria, "p", &paramCounter)
			if err != nil {
				t.Fatalf("buildSearchCriteria failed: %v", err)
			}

			// Check expected substrings
			for _, expected := range tt.expectedInQuery {
				if !strings.Contains(query, expected) && !strings.Contains(query, strings.ToLower(expected)) {
					t.Errorf("Expected query to contain %q, but it didn't.\nQuery: %s", expected, query)
				}
			}

			// Check unexpected substrings
			for _, unexpected := range tt.unexpectedInQuery {
				if strings.Contains(query, unexpected) {
					t.Errorf("Expected query NOT to contain %q, but it did.\nQuery: %s", unexpected, query)
				}
			}

			// Verify args contains the search text
			foundArg := false
			for _, arg := range args {
				if argStr, ok := arg.(string); ok {
					if strings.Contains(strings.ToLower(argStr), strings.ToLower(tt.searchText)) {
						foundArg = true
						break
					}
				}
			}
			if !foundArg {
				t.Errorf("Expected args to contain search text %q, but didn't find it in args: %+v", tt.searchText, args)
			}

			t.Logf("Generated query: %s", query)
			t.Logf("Args: %+v", args)
		})
	}
}
