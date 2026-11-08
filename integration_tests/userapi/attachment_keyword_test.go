//go:build integration

package userapi

import (
	"fmt"
	"net/http"
	"testing"
)

// TestUserAPI_HasAttachments: has_attachments follows the RFC 9979 §4 keywords
// and is omitted when the message carries neither.
func TestUserAPI_HasAttachments(t *testing.T) {
	h := newBodyStateHarness(t)
	// The harness inserts directly, so the message starts with no keywords at all,
	// like mail stored before Sora set them.
	id, _ := h.insert(t, []byte("Subject: x\r\n\r\nbody\r\n"), "this-node")
	path := fmt.Sprintf("/user/messages/%d", id)

	hasAttachments := func() (bool, bool) {
		t.Helper()
		resp := h.tc.makeRequest(t, "GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
		var msg map[string]any
		parseJSON(t, resp, &msg)
		v, present := msg["has_attachments"]
		b, _ := v.(bool)
		return b, present
	}
	patch := func(req map[string]any) {
		t.Helper()
		resp := h.tc.makeRequest(t, "PATCH", path, req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PATCH %v: status %d", req, resp.StatusCode)
		}
	}

	if _, present := hasAttachments(); present {
		t.Errorf("has_attachments present for a message without either keyword")
	}
	patch(map[string]any{"add_flags": []string{"$hasattachment"}})
	if v, present := hasAttachments(); !present || !v {
		t.Errorf("has_attachments = %v (present %v), want true", v, present)
	}
	patch(map[string]any{"add_flags": []string{"$hasnoattachment"}, "remove_flags": []string{"$hasattachment"}})
	if v, present := hasAttachments(); !present || v {
		t.Errorf("has_attachments = %v (present %v), want false", v, present)
	}
}
