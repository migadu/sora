//go:build integration

package userapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// PATCH applies additions before removals. A cancelled addition must not later
// replace the opposite attachment keyword that survived those removals.
func TestUserAPI_AttachmentFlagOverlap(t *testing.T) {
	h := newBodyStateHarness(t)
	for _, tc := range []struct {
		name, initial, want string
		add, remove         []string
	}{
		{"cancel positive keeps negative", "$hasnoattachment", "$hasnoattachment", []string{"$hasattachment"}, []string{"$hasattachment"}},
		{"cancel negative keeps positive", "$hasattachment", "$hasattachment", []string{"$hasnoattachment"}, []string{"$hasnoattachment"}},
		{"both added negative removed", "$hasnoattachment", "$hasattachment", []string{"$hasattachment", "$hasnoattachment"}, []string{"$hasnoattachment"}},
		{"both added positive removed", "$hasattachment", "$hasnoattachment", []string{"$hasattachment", "$hasnoattachment"}, []string{"$hasattachment"}},
		{"all additions cancelled", "$hasnoattachment", "", []string{"$hasattachment", "$hasnoattachment"}, []string{"$hasattachment", "$hasnoattachment"}},
		{"mixed case cancellation", "$HasNoAttachment", "$hasnoattachment", []string{"$HASATTACHMENT"}, []string{"$hasattachment"}},
		{"mixed case both added one removed", "$HasNoAttachment", "$hasattachment", []string{"$HASATTACHMENT", "$HasNoAttachment"}, []string{"$HASNOATTACHMENT"}},
		{"cancel addition with no initial keyword", "", "", []string{"$hasattachment"}, []string{"$hasattachment"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, _ := h.insert(t, []byte("Subject: overlap\r\n\r\nbody\r\n"), "this-node")
			path := fmt.Sprintf("/user/messages/%d", id)
			initial := []string{"Work", "\\Seen"}
			if tc.initial != "" {
				initial = append(initial, tc.initial)
			}
			patchAttachmentOverlap(t, h, path, initial, nil, http.StatusOK)
			patchAttachmentOverlap(t, h, path, append([]string{"Added"}, tc.add...), tc.remove, http.StatusOK)
			message := attachmentOverlapMessage(t, h, path)
			require.Contains(t, message.Flags, "\\Seen")
			require.Contains(t, message.CustomFlags, "Work")
			require.Contains(t, message.CustomFlags, "Added")
			assertAttachmentOverlapStatus(t, message, tc.want)
		})
	}
}

func TestUserAPI_AttachmentFlagOverlapKeywordCap(t *testing.T) {
	h := newBodyStateHarness(t)
	for _, tc := range []struct {
		name       string
		addExtra   bool
		wantStatus int
	}{
		{"cancelled addition leaves full message intact", false, http.StatusOK},
		{"cancelled addition cannot free the opposite slot", true, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, _ := h.insert(t, []byte("Subject: full overlap\r\n\r\nbody\r\n"), "this-node")
			path := fmt.Sprintf("/user/messages/%d", id)
			initial := []string{"$hasnoattachment", "\\Seen"}
			for i := 0; i < db.MaxCustomKeywordsPerMessage-1; i++ {
				initial = append(initial, fmt.Sprintf("kw%d", i))
			}
			patchAttachmentOverlap(t, h, path, initial, nil, http.StatusOK)
			add := []string{"$hasattachment"}
			if tc.addExtra {
				add = append(add, "Extra")
			}
			patchAttachmentOverlap(t, h, path, add, []string{"$HASATTACHMENT"}, tc.wantStatus)
			message := attachmentOverlapMessage(t, h, path)
			require.Len(t, message.CustomFlags, db.MaxCustomKeywordsPerMessage)
			require.NotContains(t, message.CustomFlags, "Extra")
			assertAttachmentOverlapStatus(t, message, "$hasnoattachment")
		})
	}
}

func patchAttachmentOverlap(t *testing.T, h *bodyStateHarness, path string, add, remove []string, status int) {
	t.Helper()
	resp := h.tc.makeRequest(t, "PATCH", path, map[string]any{"add_flags": add, "remove_flags": remove})
	defer resp.Body.Close()
	require.Equal(t, status, resp.StatusCode)
}

func attachmentOverlapMessage(t *testing.T, h *bodyStateHarness, path string) db.DBMessage {
	t.Helper()
	resp := h.tc.makeRequest(t, "GET", path, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var message db.DBMessage
	parseJSON(t, resp, &message)
	return message
}

func assertAttachmentOverlapStatus(t *testing.T, message db.DBMessage, want string) {
	t.Helper()
	for _, keyword := range []string{"$hasattachment", "$hasnoattachment"} {
		count := 0
		for _, flag := range message.CustomFlags {
			if strings.EqualFold(flag, keyword) {
				count++
			}
		}
		if strings.EqualFold(keyword, want) {
			require.Equal(t, 1, count, "%v", message.CustomFlags)
		} else {
			require.Zero(t, count, "%v", message.CustomFlags)
		}
	}
	if want == "" {
		require.Nil(t, message.HasAttachments)
	} else {
		require.NotNil(t, message.HasAttachments)
		require.Equal(t, want == "$hasattachment", *message.HasAttachments)
	}
}
