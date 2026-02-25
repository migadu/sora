package config

import (
	"testing"
	"time"
)

// --- GetFTSRetention (vector retention) tests ---

func TestGetFTSRetention_EmptyDefaultsToZero(t *testing.T) {
	cfg := CleanupConfig{}
	d, err := cfg.GetFTSRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 0 {
		t.Errorf("expected 0 (keep forever), got %v", d)
	}
}

func TestGetFTSRetention_ExplicitValue(t *testing.T) {
	cfg := CleanupConfig{FTSRetention: "1095d"}
	d, err := cfg.GetFTSRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 1095 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

func TestGetFTSRetention_InvalidValue(t *testing.T) {
	cfg := CleanupConfig{FTSRetention: "notaduration"}
	_, err := cfg.GetFTSRetention()
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestGetFTSRetentionWithDefault_InvalidFallsBackToZero(t *testing.T) {
	cfg := CleanupConfig{FTSRetention: "bad"}
	d := cfg.GetFTSRetentionWithDefault()
	if d != 0 {
		t.Errorf("expected 0 (keep forever) fallback, got %v", d)
	}
}

// --- GetFTSSourceRetention (source text retention) tests ---

func TestGetFTSSourceRetention_ExplicitValue(t *testing.T) {
	cfg := CleanupConfig{FTSSourceRetention: "365d"}
	d, err := cfg.GetFTSSourceRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 365 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected %v, got %v", expected, d)
	}
}

func TestGetFTSSourceRetention_FallsBackToFTSRetention(t *testing.T) {
	// When fts_source_retention is not set but fts_retention is,
	// source retention should fall back to fts_retention for backwards compat
	cfg := CleanupConfig{FTSRetention: "500d"}
	d, err := cfg.GetFTSSourceRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 500 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected fallback to fts_retention (%v), got %v", expected, d)
	}
}

func TestGetFTSSourceRetention_DefaultsTo2Years(t *testing.T) {
	// When both are empty, source retention defaults to 2 years
	cfg := CleanupConfig{}
	d, err := cfg.GetFTSSourceRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 730 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected 2 year default (%v), got %v", expected, d)
	}
}

func TestGetFTSSourceRetention_ExplicitOverridesFTSRetention(t *testing.T) {
	// When both are set, fts_source_retention takes priority
	cfg := CleanupConfig{
		FTSRetention:       "1095d", // 3 years for vectors
		FTSSourceRetention: "365d",  // 1 year for source
	}
	d, err := cfg.GetFTSSourceRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := 365 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected explicit source retention (%v), got %v", expected, d)
	}
}

func TestGetFTSSourceRetention_InvalidValue(t *testing.T) {
	cfg := CleanupConfig{FTSSourceRetention: "notaduration"}
	_, err := cfg.GetFTSSourceRetention()
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestGetFTSSourceRetentionWithDefault_InvalidFallsBackTo2Years(t *testing.T) {
	cfg := CleanupConfig{FTSSourceRetention: "bad"}
	d := cfg.GetFTSSourceRetentionWithDefault()
	expected := 730 * 24 * time.Hour
	if d != expected {
		t.Errorf("expected 2 year fallback (%v), got %v", expected, d)
	}
}

// --- Default config coherence ---

func TestNewDefaultConfig_FTSRetentionDefaults(t *testing.T) {
	cfg := NewDefaultConfig()

	// FTSRetention (vector) should be empty (keep forever)
	if cfg.Cleanup.FTSRetention != "" {
		t.Errorf("expected empty FTSRetention in defaults, got %q", cfg.Cleanup.FTSRetention)
	}

	// FTSSourceRetention should be "730d" (2 years)
	if cfg.Cleanup.FTSSourceRetention != "730d" {
		t.Errorf("expected FTSSourceRetention '730d' in defaults, got %q", cfg.Cleanup.FTSSourceRetention)
	}

	// Verify parsed values match expectations
	vectorRetention := cfg.Cleanup.GetFTSRetentionWithDefault()
	if vectorRetention != 0 {
		t.Errorf("expected vector retention 0 (keep forever), got %v", vectorRetention)
	}

	sourceRetention := cfg.Cleanup.GetFTSSourceRetentionWithDefault()
	expected := 730 * 24 * time.Hour
	if sourceRetention != expected {
		t.Errorf("expected source retention %v, got %v", expected, sourceRetention)
	}
}

// --- Semantic correctness: source retention should be <= vector retention ---

func TestFTSRetention_SourceShorterThanVector(t *testing.T) {
	// Typical production config: prune source text after 2y, keep vectors for 3y
	cfg := CleanupConfig{
		FTSRetention:       "1095d", // 3 years (vectors)
		FTSSourceRetention: "730d",  // 2 years (source text)
	}

	vectorRetention, err := cfg.GetFTSRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sourceRetention, err := cfg.GetFTSSourceRetention()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sourceRetention > vectorRetention {
		t.Errorf("source retention (%v) should be <= vector retention (%v) for correct semantics",
			sourceRetention, vectorRetention)
	}
}
