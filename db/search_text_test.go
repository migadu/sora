package db

import (
	"strings"
	"testing"

	"github.com/migadu/go-imap"
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
				"strpos(LOWER(m.subject),",  // Subject column (with table prefix)
				"strpos(m.from_email_sort,", // From email
				"strpos(m.from_name_sort,",  // From name
				"strpos(m.to_email_sort,",   // To email
				"strpos(m.to_name_sort,",    // To name
				"strpos(m.cc_email_sort,",   // Cc email
				"plainto_tsquery('simple',", // FTS query function
			},
			unexpectedInQuery: []string{
				"recipients_json::text", // Should NOT use JSON text casting (fragile)
				"headers_tsv",           // Should NOT use headers_tsv (removed in migration 000030)
				" LIKE ",                // Header matching must not be LIKE: it is served by the corpus-wide trigram GINs (see substringCond)
			},
		},
		{
			name:       "TEXT search with email address",
			searchText: "user@example.com",
			expectedInQuery: []string{
				"strpos(m.from_email_sort,",
				"strpos(m.to_email_sort,",
			},
		},
		{
			name:       "TEXT search with partial name",
			searchText: "Smith",
			expectedInQuery: []string{
				"strpos(m.from_name_sort,",
				"strpos(m.to_name_sort,",
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
