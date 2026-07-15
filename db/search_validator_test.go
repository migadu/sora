package db

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSearchCriteriaValidator(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	assert.Equal(t, 1000, validator.MaxSearchTermLength)
	assert.Equal(t, 50, validator.MaxSearchTerms)
	assert.Equal(t, 365*24*time.Hour, validator.MaxDateRange)
	assert.Equal(t, 10, validator.MaxTextSearchTerms)
	assert.Equal(t, 20, validator.MaxSequenceRanges)
	assert.Equal(t, 20, validator.MaxFlagFilters)

	expectedHeaders := []string{"subject", "message-id", "in-reply-to", "from", "to", "cc", "bcc", "reply-to"}
	for _, header := range expectedHeaders {
		assert.True(t, validator.SupportedHeaders[header], "Header %s should be supported", header)
	}
}

func TestValidateSearchCriteria_NilCriteria(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	result := validator.ValidateSearchCriteria(nil)

	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "criteria", result.Errors[0].Field)
	assert.Contains(t, result.Errors[0].Message, "cannot be nil")
}

func TestValidateSearchCriteria_EmptyCriteria(t *testing.T) {
	validator := NewSearchCriteriaValidator()
	criteria := &imap.SearchCriteria{}

	result := validator.ValidateSearchCriteria(criteria)

	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)
	assert.Equal(t, ComplexitySimple, result.Complexity)
}

func TestValidateSequenceRanges(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		seqNum      []imap.SeqSet
		uid         []imap.UIDSet
		expectError bool
		errorField  string
	}{
		{
			name:        "valid sequence ranges",
			seqNum:      []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 10}}},
			uid:         []imap.UIDSet{{imap.UIDRange{Start: 100, Stop: 200}}},
			expectError: false,
		},
		{
			name:        "too many sequence ranges",
			seqNum:      make([]imap.SeqSet, 25), // Exceeds MaxSequenceRanges (20)
			expectError: true,
			errorField:  "SeqNum",
		},
		{
			name:        "too many UID ranges",
			uid:         make([]imap.UIDSet, 25), // Exceeds MaxSequenceRanges (20)
			expectError: true,
			errorField:  "UID",
		},
		{
			name:        "invalid sequence range - start > stop",
			seqNum:      []imap.SeqSet{{imap.SeqRange{Start: 10, Stop: 5}}},
			expectError: true,
			errorField:  "SeqNum",
		},
		{
			name:        "invalid sequence range - zero start",
			seqNum:      []imap.SeqSet{{imap.SeqRange{Start: 0, Stop: 10}}},
			expectError: true,
			errorField:  "SeqNum",
		},
		{
			name:        "invalid UID range - start > stop",
			uid:         []imap.UIDSet{{imap.UIDRange{Start: 200, Stop: 100}}},
			expectError: true,
			errorField:  "UID",
		},
		{
			name:        "invalid UID range - zero start",
			uid:         []imap.UIDSet{{imap.UIDRange{Start: 0, Stop: 100}}},
			expectError: true,
			errorField:  "UID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := &imap.SearchCriteria{
				SeqNum: tt.seqNum,
				UID:    tt.uid,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.True(t, result.HasErrorsForField(tt.errorField))
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidateDateRanges(t *testing.T) {
	validator := NewSearchCriteriaValidator()
	now := time.Now()

	tests := []struct {
		name        string
		since       time.Time
		before      time.Time
		sentSince   time.Time
		sentBefore  time.Time
		expectError bool
	}{
		{
			name:        "valid date ranges",
			since:       now.AddDate(0, 0, -30),
			before:      now,
			sentSince:   now.AddDate(0, 0, -60),
			sentBefore:  now.AddDate(0, 0, -30),
			expectError: false,
		},
		{
			name:        "since after before",
			since:       now,
			before:      now.AddDate(0, 0, -30),
			expectError: true,
		},
		{
			name:        "sent since after sent before",
			sentSince:   now,
			sentBefore:  now.AddDate(0, 0, -30),
			expectError: true,
		},
		{
			name:        "date range too large",
			since:       now.AddDate(-2, 0, 0), // 2 years ago
			before:      now,
			expectError: true,
		},
		{
			name:        "sent date range too large",
			sentSince:   now.AddDate(-2, 0, 0), // 2 years ago
			sentBefore:  now,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := &imap.SearchCriteria{
				Since:      tt.since,
				Before:     tt.before,
				SentSince:  tt.sentSince,
				SentBefore: tt.sentBefore,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.True(t, result.HasErrorsForField("dates"))
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidateTextTerms(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		body        []string
		text        []string
		expectError bool
		errorField  string
	}{
		{
			name:        "valid text terms",
			body:        []string{"test", "email"},
			text:        []string{"subject"},
			expectError: false,
		},
		{
			name:        "too many body terms",
			body:        make([]string, 15), // Exceeds MaxTextSearchTerms (10)
			expectError: true,
			errorField:  "Body",
		},
		{
			name:        "too many text terms",
			text:        make([]string, 15), // Exceeds MaxTextSearchTerms (10)
			expectError: true,
			errorField:  "Text",
		},
		{
			name:        "empty body term",
			body:        []string{"valid", ""},
			expectError: true,
			errorField:  "Body",
		},
		{
			name:        "empty text term",
			text:        []string{"valid", ""},
			expectError: true,
			errorField:  "Text",
		},
		{
			name:        "body term too long",
			body:        []string{string(make([]byte, 1001))}, // Exceeds MaxSearchTermLength (1000)
			expectError: true,
			errorField:  "Body",
		},
		{
			name:        "text term too long",
			text:        []string{string(make([]byte, 1001))}, // Exceeds MaxSearchTermLength (1000)
			expectError: true,
			errorField:  "Text",
		},
		{
			name:        "body term with null character",
			body:        []string{"test\x00null"},
			expectError: true,
			errorField:  "Body",
		},
		{
			name:        "text term with null character",
			text:        []string{"test\x00null"},
			expectError: true,
			errorField:  "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill empty slices with valid values for length tests
			if len(tt.body) > 0 && tt.body[0] == "" && len(tt.body) > 1 {
				for i := range tt.body {
					if tt.body[i] == "" && i != 1 { // Keep one empty for the test
						tt.body[i] = "valid"
					}
				}
			}
			if len(tt.text) > 0 && tt.text[0] == "" && len(tt.text) > 1 {
				for i := range tt.text {
					if tt.text[i] == "" && i != 1 { // Keep one empty for the test
						tt.text[i] = "valid"
					}
				}
			}

			criteria := &imap.SearchCriteria{
				Body: tt.body,
				Text: tt.text,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.True(t, result.HasErrorsForField(tt.errorField))
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidateHeaders(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		headers     []imap.SearchCriteriaHeaderField
		expectError bool
	}{
		{
			name: "valid headers",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "subject", Value: "test"},
				{Key: "from", Value: "user@example.com"},
			},
			expectError: false,
		},
		{
			name: "generic header (now supported)",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "x-custom-header", Value: "test"},
			},
			expectError: false,
		},
		{
			name: "empty header value (now valid)",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "subject", Value: ""},
			},
			expectError: false,
		},
		{
			name: "header value too long",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "subject", Value: string(make([]byte, 1001))},
			},
			expectError: true,
		},
		{
			name: "message-id too long",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "message-id", Value: string(make([]byte, 256))},
			},
			expectError: true,
		},
		{
			name: "valid message-id",
			headers: []imap.SearchCriteriaHeaderField{
				{Key: "message-id", Value: "<test@example.com>"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := &imap.SearchCriteria{
				Header: tt.headers,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.NotEmpty(t, result.Errors)
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidateFlags(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		flags       []imap.Flag
		notFlags    []imap.Flag
		expectError bool
	}{
		{
			name:        "valid flags",
			flags:       []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
			notFlags:    []imap.Flag{imap.FlagDeleted},
			expectError: false,
		},
		{
			name:        "too many flag filters",
			flags:       make([]imap.Flag, 15),
			notFlags:    make([]imap.Flag, 10), // Total 25, exceeds MaxFlagFilters (20)
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill empty flag slices
			for i := range tt.flags {
				if tt.flags[i] == "" {
					tt.flags[i] = imap.Flag("test-flag")
				}
			}
			for i := range tt.notFlags {
				if tt.notFlags[i] == "" {
					tt.notFlags[i] = imap.Flag("test-not-flag")
				}
			}

			criteria := &imap.SearchCriteria{
				Flag:    tt.flags,
				NotFlag: tt.notFlags,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.True(t, result.HasErrorsForField("flags"))
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidateSizeFilters(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		larger      int64
		smaller     int64
		expectError bool
	}{
		{
			name:        "valid size filters",
			larger:      1000,
			smaller:     5000,
			expectError: false,
		},
		{
			name:        "larger >= smaller",
			larger:      5000,
			smaller:     1000,
			expectError: true,
		},
		{
			name:        "larger == smaller",
			larger:      1000,
			smaller:     1000,
			expectError: true,
		},
		{
			name:        "only larger set",
			larger:      1000,
			smaller:     0,
			expectError: false,
		},
		{
			name:        "only smaller set",
			larger:      0,
			smaller:     5000,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := &imap.SearchCriteria{
				Larger:  tt.larger,
				Smaller: tt.smaller,
			}

			result := validator.ValidateSearchCriteria(criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.True(t, result.HasErrorsForField("size"))
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestComplexityCalculation(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name               string
		criteria           *imap.SearchCriteria
		expectedComplexity SearchComplexity
	}{
		{
			name:               "simple UID search",
			criteria:           &imap.SearchCriteria{UID: []imap.UIDSet{{imap.UIDRange{Start: 1, Stop: 10}}}},
			expectedComplexity: ComplexitySimple,
		},
		{
			name: "moderate complexity",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "subject", Value: "test"},
					{Key: "from", Value: "user@example.com"},
					{Key: "to", Value: "recipient@example.com"},
				},
				Flag: []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
			},
			expectedComplexity: ComplexityModerate,
		},
		{
			name: "high complexity with text search",
			criteria: &imap.SearchCriteria{
				Text:   []string{"search term"},
				Header: []imap.SearchCriteriaHeaderField{{Key: "from", Value: "test"}},
				SeqNum: []imap.SeqSet{{imap.SeqRange{Start: 1, Stop: 100}}},
			},
			expectedComplexity: ComplexityHigh,
		},
		{
			name: "very high complexity with multiple text searches",
			criteria: &imap.SearchCriteria{
				Body: []string{"term1", "term2", "term3", "term4", "term5", "term6"},
			},
			expectedComplexity: ComplexityVeryHigh,
		},
		{
			name: "very high complexity with many body terms",
			criteria: &imap.SearchCriteria{
				Text: []string{"term1", "term2", "term3", "term4", "term5", "term6"},
			},
			expectedComplexity: ComplexityVeryHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateSearchCriteria(tt.criteria)

			assert.True(t, result.Valid)
			assert.Equal(t, tt.expectedComplexity, result.Complexity)

			// High complexity should generate warnings
			if result.Complexity >= ComplexityHigh {
				assert.NotEmpty(t, result.Warnings)
				assert.True(t, result.HasErrorsForField("complexity") || len(result.Warnings) > 0)
			}
		})
	}
}

func TestValidateNestedCriteria(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	tests := []struct {
		name        string
		criteria    *imap.SearchCriteria
		expectError bool
	}{
		{
			name: "valid NOT criteria",
			criteria: &imap.SearchCriteria{
				Not: []imap.SearchCriteria{
					{Flag: []imap.Flag{imap.FlagSeen}},
				},
			},
			expectError: false,
		},
		{
			name: "invalid NOT criteria",
			criteria: &imap.SearchCriteria{
				Not: []imap.SearchCriteria{
					{Header: []imap.SearchCriteriaHeaderField{{Key: "", Value: "test"}}}, // Empty key is invalid
				},
			},
			expectError: true,
		},
		{
			name: "valid OR criteria",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Flag: []imap.Flag{imap.FlagSeen}},
						{Flag: []imap.Flag{imap.FlagAnswered}},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid OR criteria",
			criteria: &imap.SearchCriteria{
				Or: [][2]imap.SearchCriteria{
					{
						{Header: []imap.SearchCriteriaHeaderField{{Key: "", Value: "test"}}}, // Empty key is invalid
						{Flag: []imap.Flag{imap.FlagAnswered}},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateSearchCriteria(tt.criteria)

			if tt.expectError {
				assert.False(t, result.Valid)
				assert.NotEmpty(t, result.Errors)
			} else {
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidationResult_GetFirstError(t *testing.T) {
	result := &ValidationResult{}

	// Test with no errors
	assert.Nil(t, result.GetFirstError())

	// Test with errors
	result.addError("test", "test error", nil)
	result.addError("test2", "second error", nil)

	firstErr := result.GetFirstError()
	require.NotNil(t, firstErr)
	assert.Equal(t, "search validation error in test: test error (value: <nil>)", firstErr.Error())
}

func TestValidationResult_HasErrorsForField(t *testing.T) {
	result := &ValidationResult{}

	// Test with no errors
	assert.False(t, result.HasErrorsForField("test"))

	// Test with errors
	result.addError("test", "test error", nil)
	result.addError("other", "other error", nil)

	assert.True(t, result.HasErrorsForField("test"))
	assert.True(t, result.HasErrorsForField("other"))
	assert.False(t, result.HasErrorsForField("nonexistent"))
}

func TestSearchComplexityString(t *testing.T) {
	tests := []struct {
		complexity SearchComplexity
		expected   string
	}{
		{ComplexitySimple, "simple"},
		{ComplexityModerate, "moderate"},
		{ComplexityHigh, "high"},
		{ComplexityVeryHigh, "very_high"},
		{SearchComplexity(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.complexity.String())
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{
		Field:   "test",
		Message: "test message",
		Value:   42,
	}

	expected := "search validation error in test: test message (value: 42)"
	assert.Equal(t, expected, err.Error())
}

func TestMaxTermCountValidation(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	// Create criteria that exceed the max term count
	criteria := &imap.SearchCriteria{
		Body:   make([]string, 30),                        // 30 terms
		Text:   make([]string, 25),                        // 25 terms
		Header: make([]imap.SearchCriteriaHeaderField, 5), // 5 terms
		// Total: 60 terms, exceeds MaxSearchTerms (50)
	}

	// Fill with valid values
	for i := range criteria.Body {
		criteria.Body[i] = "body"
	}
	for i := range criteria.Text {
		criteria.Text[i] = "text"
	}
	for i := range criteria.Header {
		criteria.Header[i] = imap.SearchCriteriaHeaderField{Key: "subject", Value: "test"}
	}

	result := validator.ValidateSearchCriteria(criteria)

	assert.False(t, result.Valid)
	assert.True(t, result.HasErrorsForField("total"))
}

// nestNot wraps criteria in `depth` levels of NOT, building the tree iteratively (so the
// test helper itself never recurses) — mirroring what a hostile client achieves with a
// deeply nested SEARCH command.
func nestNot(depth int) *imap.SearchCriteria {
	c := &imap.SearchCriteria{Flag: []imap.Flag{imap.FlagSeen}}
	for i := 0; i < depth; i++ {
		c = &imap.SearchCriteria{Not: []imap.SearchCriteria{*c}}
	}
	return c
}

func TestValidateSearchCriteria_NestingDepthCap(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	// At the limit: valid.
	atLimit := validator.ValidateSearchCriteria(nestNot(validator.MaxNestingDepth))
	assert.True(t, atLimit.Valid, "criteria nested exactly to the depth limit should be accepted")

	// One past the limit: rejected with a depth error.
	overLimit := validator.ValidateSearchCriteria(nestNot(validator.MaxNestingDepth + 5))
	assert.False(t, overLimit.Valid, "criteria nested past the depth limit must be rejected")
	assert.True(t, overLimit.HasErrorsForField("depth"))
}

func TestValidateSearchCriteria_DeepTreeDoesNotOverflow(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	// A pathologically deep tree (far beyond anything a 50 KiB command could carry) must
	// be rejected WITHOUT the validator recursing all the way down — proving the depth
	// guard bounds the recursion and cannot exhaust the stack. If the guard were missing,
	// this would crash the test binary with a fatal stack overflow.
	result := validator.ValidateSearchCriteria(nestNot(500_000))
	assert.False(t, result.Valid)
	assert.True(t, result.HasErrorsForField("depth"))
}

func TestValidateSearchCriteria_TotalNodeCap(t *testing.T) {
	validator := NewSearchCriteriaValidator()

	// A shallow (depth 1) but very wide tree: many sibling OR pairs at the same level.
	// This stays well under the depth cap yet would expand into a huge ORed SQL clause,
	// so it must be rejected by the total-node guard.
	wide := &imap.SearchCriteria{}
	for i := 0; i < validator.MaxTotalNodes*2; i++ {
		wide.Or = append(wide.Or, [2]imap.SearchCriteria{
			{Flag: []imap.Flag{imap.FlagSeen}},
			{Flag: []imap.Flag{imap.FlagAnswered}},
		})
	}

	result := validator.ValidateSearchCriteria(wide)
	assert.False(t, result.Valid, "a wide criteria tree exceeding the node cap must be rejected")
	assert.True(t, result.HasErrorsForField("nodes"))

	// A modest fan-out stays valid.
	small := &imap.SearchCriteria{
		Or: [][2]imap.SearchCriteria{
			{{Flag: []imap.Flag{imap.FlagSeen}}, {Flag: []imap.Flag{imap.FlagAnswered}}},
		},
	}
	assert.True(t, validator.ValidateSearchCriteria(small).Valid)
}
