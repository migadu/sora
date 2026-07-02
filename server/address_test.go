package server

import (
	"testing"
)

func TestAddressDetailParsing(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		wantFullAddress   string
		wantLocalPart     string
		wantDomain        string
		wantDetail        string
		wantBaseLocalPart string
		wantBaseAddress   string
		wantErr           bool
	}{
		{
			name:              "simple address without detail",
			input:             "user@example.com",
			wantFullAddress:   "user@example.com",
			wantLocalPart:     "user",
			wantDomain:        "example.com",
			wantDetail:        "",
			wantBaseLocalPart: "user",
			wantBaseAddress:   "user@example.com",
		},
		{
			name:              "address with detail",
			input:             "user+detail@example.com",
			wantFullAddress:   "user+detail@example.com",
			wantLocalPart:     "user+detail",
			wantDomain:        "example.com",
			wantDetail:        "detail",
			wantBaseLocalPart: "user",
			wantBaseAddress:   "user@example.com",
		},
		{
			name:              "address with complex detail",
			input:             "user+detail+more@example.com",
			wantFullAddress:   "user+detail+more@example.com",
			wantLocalPart:     "user+detail+more",
			wantDomain:        "example.com",
			wantDetail:        "detail+more",
			wantBaseLocalPart: "user",
			wantBaseAddress:   "user@example.com",
		},
		{
			name:              "address with empty detail",
			input:             "user+@example.com",
			wantFullAddress:   "user+@example.com",
			wantLocalPart:     "user+",
			wantDomain:        "example.com",
			wantDetail:        "",
			wantBaseLocalPart: "user",
			wantBaseAddress:   "user@example.com",
		},
		{
			name:              "address with plus in username",
			input:             "test.user+tag@example.com",
			wantFullAddress:   "test.user+tag@example.com",
			wantLocalPart:     "test.user+tag",
			wantDomain:        "example.com",
			wantDetail:        "tag",
			wantBaseLocalPart: "test.user",
			wantBaseAddress:   "test.user@example.com",
		},
		{
			name:              "address with special characters and detail",
			input:             "test_user+detail@example.com",
			wantFullAddress:   "test_user+detail@example.com",
			wantLocalPart:     "test_user+detail",
			wantDomain:        "example.com",
			wantDetail:        "detail",
			wantBaseLocalPart: "test_user",
			wantBaseAddress:   "test_user@example.com",
		},
		{
			name:              "uppercase address with detail",
			input:             "USER+DETAIL@EXAMPLE.COM",
			wantFullAddress:   "user+detail@example.com",
			wantLocalPart:     "user+detail",
			wantDomain:        "example.com",
			wantDetail:        "detail",
			wantBaseLocalPart: "user",
			wantBaseAddress:   "user@example.com",
		},
		{
			// Constant Contact and other ESPs use base64/VERP-style reverse-paths
			// whose local part contains "/", "+" and "=". These are all valid RFC 5321
			// atext and must be accepted, otherwise legitimate mail bounces.
			name:              "base64/VERP local part with slash",
			input:             "Ap+Iao+8tQk6GgWD4E/IMCg==_1140208144979_MPP2bPipEe2HevoWPpr49g==@in.constantcontact.com",
			wantFullAddress:   "ap+iao+8tqk6ggwd4e/imcg==_1140208144979_mpp2bpipee2hevowppr49g==@in.constantcontact.com",
			wantLocalPart:     "ap+iao+8tqk6ggwd4e/imcg==_1140208144979_mpp2bpipee2hevowppr49g==",
			wantDomain:        "in.constantcontact.com",
			wantDetail:        "iao+8tqk6ggwd4e/imcg==_1140208144979_mpp2bpipee2hevowppr49g==",
			wantBaseLocalPart: "ap",
			wantBaseAddress:   "ap@in.constantcontact.com",
		},
		{
			// Backtick is atext (RFC 5322 §3.2.3) and must be accepted.
			name:              "backtick in local part",
			input:             "weird`name@example.com",
			wantFullAddress:   "weird`name@example.com",
			wantLocalPart:     "weird`name",
			wantDomain:        "example.com",
			wantDetail:        "",
			wantBaseLocalPart: "weird`name",
			wantBaseAddress:   "weird`name@example.com",
		},
		{
			name:    "invalid address",
			input:   "invalid-email",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if got := addr.FullAddress(); got != tt.wantFullAddress {
				t.Errorf("FullAddress() = %v, want %v", got, tt.wantFullAddress)
			}
			if got := addr.LocalPart(); got != tt.wantLocalPart {
				t.Errorf("LocalPart() = %v, want %v", got, tt.wantLocalPart)
			}
			if got := addr.Domain(); got != tt.wantDomain {
				t.Errorf("Domain() = %v, want %v", got, tt.wantDomain)
			}
			if got := addr.Detail(); got != tt.wantDetail {
				t.Errorf("Detail() = %v, want %v", got, tt.wantDetail)
			}
			if got := addr.BaseLocalPart(); got != tt.wantBaseLocalPart {
				t.Errorf("BaseLocalPart() = %v, want %v", got, tt.wantBaseLocalPart)
			}
			if got := addr.BaseAddress(); got != tt.wantBaseAddress {
				t.Errorf("BaseAddress() = %v, want %v", got, tt.wantBaseAddress)
			}
		})
	}
}
