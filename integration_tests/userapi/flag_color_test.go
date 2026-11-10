//go:build integration

package userapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestUserAPI_UnflagClearsFlagColor: as for IMAP STORE, removing \Flagged also
// removes the RFC 9979 flag color keywords (RFC 9979 §3.2).
func TestUserAPI_UnflagClearsFlagColor(t *testing.T) {
	h := newBodyStateHarness(t)
	id, _ := h.insert(t, []byte("Subject: x\r\n\r\nbody\r\n"), "this-node")
	path := fmt.Sprintf("/user/messages/%d", id)

	resp := h.tc.makeRequest(t, "PATCH", path, map[string]any{"add_flags": []string{"\\Flagged", "$MailFlagBit0", "$MailFlagBit2", "Work"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("flag with a color: status %d", resp.StatusCode)
	}

	resp = h.tc.makeRequest(t, "PATCH", path, map[string]any{"remove_flags": []string{"\\Flagged"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unflag: status %d", resp.StatusCode)
	}

	resp = h.tc.makeRequest(t, "GET", path, nil)
	var msg struct {
		Flags       []string `json:"flags"`
		CustomFlags []string `json:"custom_flags"`
	}
	parseJSON(t, resp, &msg)
	for _, f := range msg.Flags {
		if f == "\\Flagged" {
			t.Errorf("flags = %v, want \\Flagged removed", msg.Flags)
		}
	}
	for _, k := range msg.CustomFlags {
		if strings.HasPrefix(strings.ToLower(k), "$mailflagbit") {
			t.Errorf("custom_flags = %v, want the color keywords removed with \\Flagged", msg.CustomFlags)
		}
	}
	if len(msg.CustomFlags) != 1 || msg.CustomFlags[0] != "Work" {
		t.Errorf("custom_flags = %v, want only Work left", msg.CustomFlags)
	}
}

func TestUserAPI_AddFlagColorRequiresFlagged(t *testing.T) {
	h := newBodyStateHarness(t)
	for _, tc := range []struct {
		name                 string
		initial, add, remove []string
		wantColor            bool
	}{
		{"unflagged", nil, []string{"$MailFlagBit0", "Work"}, nil, false},
		{"flagged in same update", nil, []string{"$MailFlagBit0", "\\Flagged", "Work"}, nil, true},
		{"already flagged", []string{"\\Flagged"}, []string{"$mailflagbit0", "Work"}, nil, true},
		{"flagged removed in same update", []string{"\\Flagged"}, []string{"$MAILFLAGBIT0", "Work"}, []string{"\\Flagged"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, _ := h.insert(t, []byte("Subject: color\r\n\r\nbody\r\n"), "this-node")
			path := fmt.Sprintf("/user/messages/%d", id)
			if len(tc.initial) > 0 {
				resp := h.tc.makeRequest(t, "PATCH", path, map[string]any{"add_flags": tc.initial})
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("initial flags: status %d", resp.StatusCode)
				}
			}
			resp := h.tc.makeRequest(t, "PATCH", path, map[string]any{"add_flags": tc.add, "remove_flags": tc.remove})
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("update: status %d", resp.StatusCode)
			}
			resp = h.tc.makeRequest(t, "GET", path, nil)
			var msg struct {
				CustomFlags []string `json:"custom_flags"`
			}
			parseJSON(t, resp, &msg)
			hasColor, hasWork := false, false
			for _, flag := range msg.CustomFlags {
				hasColor = hasColor || strings.EqualFold(flag, "$MailFlagBit0")
				hasWork = hasWork || flag == "Work"
			}
			if hasColor != tc.wantColor || !hasWork {
				t.Errorf("custom flags = %v, want color=%v and Work", msg.CustomFlags, tc.wantColor)
			}
		})
	}
}
