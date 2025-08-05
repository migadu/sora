package main

import (
	"strings"
	"testing"
)

func TestParseDovecotUIDList(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    *DovecotUIDList
		wantErr bool
	}{
		{
			name: "valid uidlist with multiple mappings",
			content: `3 V1275660208 N25022 G3085f01b7f11094c501100008c4a11c1
25006 :1276528487.M364837P9451.kurkku,S=1355,W=1394:2,
25017 W2481 :1276533073.M242911P3632.kurkku:2,F
25020 :1276533074.M242912P3633.kurkku,S=2000:2,S`,
			want: &DovecotUIDList{
				Version:     3,
				UIDValidity: 1275660208,
				NextUID:     25022,
				GlobalUID:   "3085f01b7f11094c501100008c4a11c1",
				UIDMappings: map[string]uint32{
					"1276528487.M364837P9451.kurkku": 25006,
					"1276533073.M242911P3632.kurkku": 25017,
					"1276533074.M242912P3633.kurkku": 25020,
				},
			},
			wantErr: false,
		},
		{
			name: "version 1 uidlist",
			content: `1 V1234567890 N100
1 :1234567890.M1P1.hostname:2,S
2 :1234567891.M2P2.hostname:2,`,
			want: &DovecotUIDList{
				Version:     1,
				UIDValidity: 1234567890,
				NextUID:     100,
				UIDMappings: map[string]uint32{
					"1234567890.M1P1.hostname": 1,
					"1234567891.M2P2.hostname": 2,
				},
			},
			wantErr: false,
		},
		{
			name:    "empty file",
			content: "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "missing UIDVALIDITY",
			content: "3 N25022 G3085f01b7f11094c501100008c4a11c1",
			want:    nil,
			wantErr: true,
		},
		{
			name: "malformed UID mapping",
			content: `3 V1275660208 N25022
invalid line without colon`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.content)
			got, err := parseDovecotUIDListFromReader(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseDovecotUIDListFromReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got.Version != tt.want.Version {
					t.Errorf("Version = %v, want %v", got.Version, tt.want.Version)
				}
				if got.UIDValidity != tt.want.UIDValidity {
					t.Errorf("UIDValidity = %v, want %v", got.UIDValidity, tt.want.UIDValidity)
				}
				if got.NextUID != tt.want.NextUID {
					t.Errorf("NextUID = %v, want %v", got.NextUID, tt.want.NextUID)
				}
				if got.GlobalUID != tt.want.GlobalUID {
					t.Errorf("GlobalUID = %v, want %v", got.GlobalUID, tt.want.GlobalUID)
				}
				if len(got.UIDMappings) != len(tt.want.UIDMappings) {
					t.Errorf("UIDMappings length = %v, want %v", len(got.UIDMappings), len(tt.want.UIDMappings))
				}
				t.Logf("Got mappings: %+v", got.UIDMappings)
				t.Logf("Want mappings: %+v", tt.want.UIDMappings)
				for k, v := range tt.want.UIDMappings {
					if got.UIDMappings[k] != v {
						t.Errorf("UIDMappings[%s] = %v, want %v", k, got.UIDMappings[k], v)
					}
				}
			}
		})
	}
}

func TestGetUIDForFile(t *testing.T) {
	uidList := &DovecotUIDList{
		UIDMappings: map[string]uint32{
			"1276528487.M364837P9451.kurkku": 25006,
			"1276533073.M242911P3632.kurkku": 25017,
		},
	}

	tests := []struct {
		name     string
		filename string
		wantUID  uint32
		wantOK   bool
	}{
		{
			name:     "exact match",
			filename: "1276528487.M364837P9451.kurkku",
			wantUID:  25006,
			wantOK:   true,
		},
		{
			name:     "match with flags suffix",
			filename: "1276528487.M364837P9451.kurkku:2,S",
			wantUID:  25006,
			wantOK:   true,
		},
		{
			name:     "match with different flags",
			filename: "1276533073.M242911P3632.kurkku:2,FS",
			wantUID:  25017,
			wantOK:   true,
		},
		{
			name:     "no match",
			filename: "1234567890.M999P999.hostname:2,S",
			wantUID:  0,
			wantOK:   false,
		},
		{
			name:     "with path prefix",
			filename: "/path/to/maildir/cur/1276528487.M364837P9451.kurkku:2,S",
			wantUID:  25006,
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUID, gotOK := uidList.GetUIDForFile(tt.filename)
			if gotUID != tt.wantUID || gotOK != tt.wantOK {
				t.Errorf("GetUIDForFile(%s) = (%v, %v), want (%v, %v)",
					tt.filename, gotUID, gotOK, tt.wantUID, tt.wantOK)
			}
		})
	}
}

func TestWriteDovecotUIDList(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	
	// Create test UID list
	uidList := &DovecotUIDList{
		Version:     3,
		UIDValidity: 1234567890,
		NextUID:     100,
		GlobalUID:   "test123456789abcdef",
		UIDMappings: map[string]uint32{
			"1234567890.M1P1.hostname": 1,
			"1234567891.M2P2.hostname": 2,
			"1234567892.M3P3.hostname": 50,
		},
	}
	
	// Write UID list
	err := WriteDovecotUIDList(tempDir, uidList)
	if err != nil {
		t.Fatalf("WriteDovecotUIDList failed: %v", err)
	}
	
	// Read back and verify
	readUIDList, err := ParseDovecotUIDList(tempDir)
	if err != nil {
		t.Fatalf("ParseDovecotUIDList failed: %v", err)
	}
	
	// Verify the content
	if readUIDList.Version != uidList.Version {
		t.Errorf("Version = %v, want %v", readUIDList.Version, uidList.Version)
	}
	if readUIDList.UIDValidity != uidList.UIDValidity {
		t.Errorf("UIDValidity = %v, want %v", readUIDList.UIDValidity, uidList.UIDValidity)
	}
	if readUIDList.NextUID != uidList.NextUID {
		t.Errorf("NextUID = %v, want %v", readUIDList.NextUID, uidList.NextUID)
	}
	if readUIDList.GlobalUID != uidList.GlobalUID {
		t.Errorf("GlobalUID = %v, want %v", readUIDList.GlobalUID, uidList.GlobalUID)
	}
	
	for filename, expectedUID := range uidList.UIDMappings {
		if actualUID, ok := readUIDList.UIDMappings[filename]; !ok {
			t.Errorf("Missing UID mapping for %s", filename)
		} else if actualUID != expectedUID {
			t.Errorf("UIDMappings[%s] = %v, want %v", filename, actualUID, expectedUID)
		}
	}
}

func TestCreateDovecotUIDListFromMessages(t *testing.T) {
	messages := []UIDFileMapping{
		{UID: 1, Filename: "1234567890.M1P1.hostname"},
		{UID: 5, Filename: "1234567891.M2P2.hostname"},
		{UID: 10, Filename: "1234567892.M3P3.hostname"},
	}
	
	uidList := CreateDovecotUIDListFromMessages(1234567890, messages)
	
	if uidList.Version != 3 {
		t.Errorf("Version = %v, want 3", uidList.Version)
	}
	if uidList.UIDValidity != 1234567890 {
		t.Errorf("UIDValidity = %v, want 1234567890", uidList.UIDValidity)
	}
	if uidList.NextUID != 11 {
		t.Errorf("NextUID = %v, want 11", uidList.NextUID)
	}
	
	expectedMappings := map[string]uint32{
		"1234567890.M1P1.hostname": 1,
		"1234567891.M2P2.hostname": 5,
		"1234567892.M3P3.hostname": 10,
	}
	
	for filename, expectedUID := range expectedMappings {
		if actualUID, ok := uidList.UIDMappings[filename]; !ok {
			t.Errorf("Missing UID mapping for %s", filename)
		} else if actualUID != expectedUID {
			t.Errorf("UIDMappings[%s] = %v, want %v", filename, actualUID, expectedUID)
		}
	}
}