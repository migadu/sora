package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
)

// SearchCriteriaValidator handles validation of IMAP search criteria
type SearchCriteriaValidator struct {
	MaxSearchTermLength int
	MaxSearchTerms      int
	MaxDateRange        time.Duration
	MaxTextSearchTerms  int
	SupportedHeaders    map[string]bool
	MaxSequenceRanges   int
	MaxFlagFilters      int
}

// NewSearchCriteriaValidator creates a new validator with sensible defaults
func NewSearchCriteriaValidator() *SearchCriteriaValidator {
	return &SearchCriteriaValidator{
		MaxSearchTermLength: 1000,                 // Max characters in a single search term
		MaxSearchTerms:      50,                   // Max total search terms across all criteria
		MaxDateRange:        365 * 24 * time.Hour, // Max 1 year date range
		MaxTextSearchTerms:  10,                   // Max body/text search terms
		MaxSequenceRanges:   20,                   // Max UID/sequence ranges
		MaxFlagFilters:      20,                   // Max flag conditions
		SupportedHeaders: map[string]bool{
			"subject":     true,
			"message-id":  true,
			"in-reply-to": true,
			"from":        true,
			"to":          true,
			"cc":          true,
			"bcc":         true,
			"reply-to":    true,
		},
	}
}

// ValidationError represents a search criteria validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("search validation error in %s: %s (value: %v)", e.Field, e.Message, e.Value)
}

// ValidationResult holds the results of search criteria validation
type ValidationResult struct {
	Valid      bool
	Errors     []*ValidationError
	Warnings   []*ValidationError
	Complexity SearchComplexity
}

// SearchComplexity indicates the complexity level of a search query
type SearchComplexity int

const (
	ComplexitySimple SearchComplexity = iota
	ComplexityModerate
	ComplexityHigh
	ComplexityVeryHigh
)

func (c SearchComplexity) String() string {
	switch c {
	case ComplexitySimple:
		return "simple"
	case ComplexityModerate:
		return "moderate"
	case ComplexityHigh:
		return "high"
	case ComplexityVeryHigh:
		return "very_high"
	default:
		return "unknown"
	}
}

// ValidateSearchCriteria validates IMAP search criteria and returns detailed results
func (v *SearchCriteriaValidator) ValidateSearchCriteria(criteria *imap.SearchCriteria) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []*ValidationError{},
		Warnings: []*ValidationError{},
	}

	if criteria == nil {
		result.addError("criteria", "search criteria cannot be nil", nil)
		return result
	}

	// Count and validate different aspects
	termCount := 0
	complexityScore := 0

	// Validate sequence number ranges
	if err := v.validateSeqSets(criteria.SeqNum, "SeqNum"); err != nil {
		result.addError("SeqNum", err.Error(), criteria.SeqNum)
	}
	complexityScore += len(criteria.SeqNum) * 2 // Sequence searches are moderately complex

	// Validate UID ranges
	if err := v.validateUIDSets(criteria.UID, "UID"); err != nil {
		result.addError("UID", err.Error(), criteria.UID)
	}
	complexityScore += len(criteria.UID)

	// Validate date ranges
	if err := v.validateDateRanges(criteria); err != nil {
		result.addError("dates", err.Error(), nil)
	}

	// Validate size filters
	if criteria.Larger > 0 && criteria.Smaller > 0 && criteria.Larger >= criteria.Smaller {
		result.addError("size", "larger value must be less than smaller value",
			map[string]int64{"larger": criteria.Larger, "smaller": criteria.Smaller})
	}

	// Validate text search terms
	if err := v.validateTextTerms(criteria.Body, "Body"); err != nil {
		result.addError("Body", err.Error(), criteria.Body)
	}
	termCount += len(criteria.Body)
	complexityScore += len(criteria.Body) * 3 // Text search is expensive

	if err := v.validateTextTerms(criteria.Text, "Text"); err != nil {
		result.addError("Text", err.Error(), criteria.Text)
	}
	termCount += len(criteria.Text)
	complexityScore += len(criteria.Text) * 4 // Text search in headers+body is very expensive

	// Validate flags
	if len(criteria.Flag)+len(criteria.NotFlag) > v.MaxFlagFilters {
		result.addError("flags", fmt.Sprintf("too many flag filters: %d (max: %d)",
			len(criteria.Flag)+len(criteria.NotFlag), v.MaxFlagFilters), nil)
	}

	// Validate headers
	for i, header := range criteria.Header {
		if err := v.validateHeader(header); err != nil {
			result.addError(fmt.Sprintf("Header[%d]", i), err.Error(), header)
		}
		termCount++
	}
	complexityScore += len(criteria.Header) * 2

	// Validate recursive criteria (NOT, OR)
	for i, notCriteria := range criteria.Not {
		subResult := v.ValidateSearchCriteria(&notCriteria)
		if !subResult.Valid {
			for _, err := range subResult.Errors {
				result.addError(fmt.Sprintf("Not[%d].%s", i, err.Field), err.Message, err.Value)
			}
		}
		complexityScore += 3 // NOT adds complexity
	}

	for i, orPair := range criteria.Or {
		for j, orCriteria := range orPair {
			subResult := v.ValidateSearchCriteria(&orCriteria)
			if !subResult.Valid {
				for _, err := range subResult.Errors {
					result.addError(fmt.Sprintf("Or[%d][%d].%s", i, j, err.Field), err.Message, err.Value)
				}
			}
		}
		complexityScore += 2 // OR adds complexity
	}

	// Check total term count
	if termCount > v.MaxSearchTerms {
		result.addError("total", fmt.Sprintf("too many search terms: %d (max: %d)",
			termCount, v.MaxSearchTerms), termCount)
	}

	// Determine complexity
	result.Complexity = v.calculateComplexity(complexityScore, criteria)

	// Add warnings for high complexity
	if result.Complexity >= ComplexityHigh {
		result.addWarning("complexity", fmt.Sprintf("search query has %s complexity (score: %d)",
			result.Complexity.String(), complexityScore), complexityScore)
	}

	return result
}

func (v *SearchCriteriaValidator) validateSeqSets(seqSets []imap.SeqSet, fieldName string) error {
	if len(seqSets) > v.MaxSequenceRanges {
		return fmt.Errorf("too many %s ranges: %d (max: %d)", fieldName, len(seqSets), v.MaxSequenceRanges)
	}

	for i, seqSet := range seqSets {
		for j, r := range seqSet {
			if r.Start > r.Stop && r.Stop != 0 {
				return fmt.Errorf("%s[%d][%d]: start (%d) must be <= stop (%d)",
					fieldName, i, j, r.Start, r.Stop)
			}
			if r.Start == 0 {
				return fmt.Errorf("%s[%d][%d]: sequence numbers must be >= 1", fieldName, i, j)
			}
		}
	}
	return nil
}

func (v *SearchCriteriaValidator) validateUIDSets(uidSets []imap.UIDSet, fieldName string) error {
	if len(uidSets) > v.MaxSequenceRanges {
		return fmt.Errorf("too many %s ranges: %d (max: %d)", fieldName, len(uidSets), v.MaxSequenceRanges)
	}

	for i, uidSet := range uidSets {
		for j, r := range uidSet {
			if r.Start > r.Stop && r.Stop != 0 {
				return fmt.Errorf("%s[%d][%d]: start (%d) must be <= stop (%d)",
					fieldName, i, j, r.Start, r.Stop)
			}
			if r.Start == 0 {
				return fmt.Errorf("%s[%d][%d]: UIDs must be >= 1", fieldName, i, j)
			}
		}
	}
	return nil
}

func (v *SearchCriteriaValidator) validateDateRanges(criteria *imap.SearchCriteria) error {
	// Check individual date validity
	if !criteria.Since.IsZero() && !criteria.Before.IsZero() {
		if criteria.Since.After(criteria.Before) {
			return fmt.Errorf("since date (%v) must be before Before date (%v)", criteria.Since, criteria.Before)
		}
		if criteria.Before.Sub(criteria.Since) > v.MaxDateRange {
			return fmt.Errorf("date range too large: %v (max: %v)", criteria.Before.Sub(criteria.Since), v.MaxDateRange)
		}
	}

	if !criteria.SentSince.IsZero() && !criteria.SentBefore.IsZero() {
		if criteria.SentSince.After(criteria.SentBefore) {
			return fmt.Errorf("SentSince date (%v) must be before SentBefore date (%v)", criteria.SentSince, criteria.SentBefore)
		}
		if criteria.SentBefore.Sub(criteria.SentSince) > v.MaxDateRange {
			return fmt.Errorf("sent date range too large: %v (max: %v)", criteria.SentBefore.Sub(criteria.SentSince), v.MaxDateRange)
		}
	}

	return nil
}

func (v *SearchCriteriaValidator) validateTextTerms(terms []string, fieldName string) error {
	if len(terms) > v.MaxTextSearchTerms {
		return fmt.Errorf("too many %s search terms: %d (max: %d)", fieldName, len(terms), v.MaxTextSearchTerms)
	}

	for i, term := range terms {
		if len(term) == 0 {
			return fmt.Errorf("%s[%d]: search term cannot be empty", fieldName, i)
		}
		if len(term) > v.MaxSearchTermLength {
			return fmt.Errorf("%s[%d]: search term too long: %d characters (max: %d)",
				fieldName, i, len(term), v.MaxSearchTermLength)
		}
		// Check for potentially problematic characters
		if strings.Contains(term, "\x00") {
			return fmt.Errorf("%s[%d]: search term contains null characters", fieldName, i)
		}
	}
	return nil
}

func (v *SearchCriteriaValidator) validateHeader(header imap.SearchCriteriaHeaderField) error {
	// Check if header is supported
	if !v.SupportedHeaders[strings.ToLower(header.Key)] {
		return fmt.Errorf("unsupported header field: %s", header.Key)
	}

	// Validate header value
	if len(header.Value) == 0 {
		return fmt.Errorf("header value cannot be empty for field: %s", header.Key)
	}
	if len(header.Value) > v.MaxSearchTermLength {
		return fmt.Errorf("header value too long: %d characters (max: %d)",
			len(header.Value), v.MaxSearchTermLength)
	}

	// Specific validation for certain headers
	switch strings.ToLower(header.Key) {
	case "message-id", "in-reply-to":
		// Message IDs should be reasonable length and format
		value := strings.TrimSpace(header.Value)
		if len(value) > 255 {
			return fmt.Errorf("%s value too long: %d characters (max: 255)", header.Key, len(value))
		}
	}

	return nil
}

func (v *SearchCriteriaValidator) calculateComplexity(score int, criteria *imap.SearchCriteria) SearchComplexity {
	// Base complexity on score and specific expensive operations
	if len(criteria.Text) > 5 || len(criteria.Body) > 5 {
		return ComplexityVeryHigh
	}
	if len(criteria.Text) > 0 || len(criteria.Body) > 0 {
		score += 10 // Text search is expensive
	}
	if len(criteria.SeqNum) > 0 {
		score += 5 // Sequence number calculation is expensive
	}

	switch {
	case score <= 5:
		return ComplexitySimple
	case score <= 15:
		return ComplexityModerate
	case score <= 30:
		return ComplexityHigh
	default:
		return ComplexityVeryHigh
	}
}

// Helper methods for ValidationResult
func (r *ValidationResult) addError(field, message string, value interface{}) {
	r.Valid = false
	r.Errors = append(r.Errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

func (r *ValidationResult) addWarning(field, message string, value interface{}) {
	r.Warnings = append(r.Warnings, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// GetFirstError returns the first validation error or nil if no errors
func (r *ValidationResult) GetFirstError() error {
	if len(r.Errors) > 0 {
		return r.Errors[0]
	}
	return nil
}

// HasErrorsForField checks if there are validation errors for a specific field
func (r *ValidationResult) HasErrorsForField(field string) bool {
	for _, err := range r.Errors {
		if err.Field == field {
			return true
		}
	}
	return false
}
