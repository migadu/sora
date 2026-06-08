package db

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
)

func TestIsCriteriaSearchAll(t *testing.T) {
	tests := []struct {
		name     string
		criteria *imap.SearchCriteria
		want     bool
	}{
		{
			name:     "nil criteria is SEARCH ALL",
			criteria: nil,
			want:     true,
		},
		{
			name:     "empty criteria is SEARCH ALL",
			criteria: &imap.SearchCriteria{},
			want:     true,
		},
		{
			name: "criteria with UID is not SEARCH ALL",
			criteria: &imap.SearchCriteria{
				UID: []imap.UIDSet{imap.UIDSetNum(1)},
			},
			want: false,
		},
		{
			name: "criteria with Header is not SEARCH ALL",
			criteria: &imap.SearchCriteria{
				Header: []imap.SearchCriteriaHeaderField{
					{Key: "Subject", Value: "test"},
				},
			},
			want: false,
		},
		{
			name: "criteria with Larger is not SEARCH ALL",
			criteria: &imap.SearchCriteria{
				Larger: 100,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCriteriaSearchAll(tt.criteria)
			if got != tt.want {
				t.Errorf("isCriteriaSearchAll() = %v, want %v", got, tt.want)
			}
		})
	}
}
