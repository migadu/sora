//go:build integration

package userapi

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// patchFlags sends PATCH /user/messages/{id} and returns the status and the
// decoded body.
func (h *bodyStateHarness) patchFlags(t *testing.T, id int64, req map[string]any) (int, map[string]any) {
	t.Helper()
	resp := h.tc.makeRequest(t, "PATCH", fmt.Sprintf("/user/messages/%d", id), req)
	var body map[string]any
	parseJSON(t, resp, &body)
	return resp.StatusCode, body
}

// getFlags returns the message's flags and custom_flags as the API reports them.
func (h *bodyStateHarness) getFlags(t *testing.T, id int64) (flags, custom []string) {
	t.Helper()
	resp := h.tc.makeRequest(t, "GET", fmt.Sprintf("/user/messages/%d", id), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET message %d: status %d", id, resp.StatusCode)
	}
	var msg struct {
		Flags       []string `json:"flags"`
		CustomFlags []string `json:"custom_flags"`
	}
	parseJSON(t, resp, &msg)
	return msg.Flags, msg.CustomFlags
}

// TestUserAPI_MessageFlags_Spelling pins the flag spelling the API accepts and
// returns: system flags with their backslash in any case, keywords without one,
// and never \Recent.
func TestUserAPI_MessageFlags_Spelling(t *testing.T) {
	h := newBodyStateHarness(t)
	id, _ := h.insert(t, []byte("Subject: x\r\n\r\nbody\r\n"), "this-node")

	t.Run("system flag in any case and a keyword", func(t *testing.T) {
		status, body := h.patchFlags(t, id, map[string]any{"add_flags": []string{"\\seen", "\\FLAGGED", "Work"}})
		if status != http.StatusOK {
			t.Fatalf("status %d, body %v", status, body)
		}
		flags, custom := h.getFlags(t, id)
		if !slices.Contains(flags, "\\Seen") || !slices.Contains(flags, "\\Flagged") {
			t.Errorf("flags = %v, want \\Seen and \\Flagged", flags)
		}
		if !slices.Contains(custom, "Work") {
			t.Errorf("custom_flags = %v, want Work", custom)
		}
	})

	t.Run("bare system flag name is refused, not stored as a keyword", func(t *testing.T) {
		for _, field := range []string{"add_flags", "remove_flags"} {
			status, body := h.patchFlags(t, id, map[string]any{field: []string{"Draft"}})
			if status != http.StatusBadRequest {
				t.Fatalf("%s [Draft]: status %d, want 400 (body %v)", field, status, body)
			}
			if msg, _ := body["error"].(string); !strings.Contains(msg, "\\Draft") {
				t.Errorf("%s [Draft]: error %q does not point to \\Draft", field, msg)
			}
		}
		_, custom := h.getFlags(t, id)
		if slices.ContainsFunc(custom, func(k string) bool { return strings.EqualFold(k, "Draft") }) {
			t.Errorf("custom_flags = %v: a bare Draft must not become a keyword", custom)
		}
	})

	t.Run("Recent cannot be set or cleared", func(t *testing.T) {
		for _, field := range []string{"add_flags", "remove_flags"} {
			if status, body := h.patchFlags(t, id, map[string]any{field: []string{"\\Recent"}}); status != http.StatusBadRequest {
				t.Errorf("%s [\\Recent]: status %d, want 400 (body %v)", field, status, body)
			}
		}
	})

	t.Run("stale stored Recent bit is not reported", func(t *testing.T) {
		// Rows written before IMAP stopped storing \Recent can still carry bit 32.
		h.exec(t, `UPDATE message_state SET flags = flags | 32 WHERE message_id = $1`, id)
		flags, _ := h.getFlags(t, id)
		if slices.Contains(flags, "\\Recent") {
			t.Errorf("flags = %v, want no \\Recent", flags)
		}
	})
}
