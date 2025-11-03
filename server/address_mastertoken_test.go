package server

import (
	"testing"
)

func TestParseAddressWithMasterToken(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectError  bool
		expectAddr   string
		expectDomain string
		expectLocal  string
		expectDetail string
		expectToken  string
		expectBase   string
		expectMaster string
	}{
		{
			name:         "simple email",
			input:        "user@example.com",
			expectError:  false,
			expectAddr:   "user@example.com",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectToken:  "",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com",
		},
		{
			name:         "email with +detail",
			input:        "user+tag@example.com",
			expectError:  false,
			expectAddr:   "user+tag@example.com",
			expectDomain: "example.com",
			expectLocal:  "user+tag",
			expectDetail: "tag",
			expectToken:  "",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com",
		},
		{
			name:         "email with master token",
			input:        "user@example.com@TOKEN",
			expectError:  false,
			expectAddr:   "user@example.com@token",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectToken:  "token",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com@token",
		},
		{
			name:         "email with +detail and master token",
			input:        "user+tag@example.com@TOKEN",
			expectError:  false,
			expectAddr:   "user+tag@example.com@token",
			expectDomain: "example.com",
			expectLocal:  "user+tag",
			expectDetail: "tag",
			expectToken:  "token",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com@token",
		},
		{
			name:        "invalid - no @",
			input:       "userexample.com",
			expectError: true,
		},
		{
			name:        "invalid - empty",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid - whitespace only",
			input:       "   ",
			expectError: true,
		},
		{
			name:        "invalid - internal space",
			input:       "user @example.com",
			expectError: true,
		},
		{
			name:         "suffix with @ character",
			input:        "user@example.com@token@extra",
			expectError:  false,
			expectAddr:   "user@example.com@token@extra",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectToken:  "token@extra", // Suffix can contain @ characters
			expectBase:   "user@example.com",
			expectMaster: "user@example.com@token@extra",
		},
		{
			name:         "trimming spaces",
			input:        "  user@example.com  ",
			expectError:  false,
			expectAddr:   "user@example.com",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectToken:  "",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com",
		},
		{
			name:         "uppercase normalized",
			input:        "User@Example.COM",
			expectError:  false,
			expectAddr:   "user@example.com",
			expectDomain: "example.com",
			expectLocal:  "user",
			expectDetail: "",
			expectToken:  "",
			expectBase:   "user@example.com",
			expectMaster: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewAddress(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if addr.FullAddress() != tt.expectAddr {
				t.Errorf("FullAddress: expected '%s', got '%s'", tt.expectAddr, addr.FullAddress())
			}
			if addr.Domain() != tt.expectDomain {
				t.Errorf("Domain: expected '%s', got '%s'", tt.expectDomain, addr.Domain())
			}
			if addr.LocalPart() != tt.expectLocal {
				t.Errorf("LocalPart: expected '%s', got '%s'", tt.expectLocal, addr.LocalPart())
			}
			if addr.Detail() != tt.expectDetail {
				t.Errorf("Detail: expected '%s', got '%s'", tt.expectDetail, addr.Detail())
			}
			if addr.MasterToken() != tt.expectToken {
				t.Errorf("MasterToken: expected '%s', got '%s'", tt.expectToken, addr.MasterToken())
			}
			if addr.BaseAddress() != tt.expectBase {
				t.Errorf("BaseAddress: expected '%s', got '%s'", tt.expectBase, addr.BaseAddress())
			}
			if addr.MasterAddress() != tt.expectMaster {
				t.Errorf("MasterAddress: expected '%s', got '%s'", tt.expectMaster, addr.MasterAddress())
			}
		})
	}
}
