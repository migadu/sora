//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// DELETE /admin/accounts/{email}?purge=true is a request, not the purge itself: the Admin
// API takes the account out of service, ends its sessions, marks it for purging and
// answers 202. A purge worker on a node that has object storage does the deletion. So the
// request works on any node, a proxy without S3 included, and these tests run it on a
// stack with no storage at all.

// purgeMark reads the account's purge request time, nil when it is not marked.
func (s *purgeStack) purgeMark(t *testing.T, accountID int64) *time.Time {
	t.Helper()
	var mark *time.Time
	if err := s.rdb.QueryRowWithRetry(context.Background(),
		`SELECT purge_requested_at FROM accounts WHERE id = $1`, accountID).Scan(&mark); err != nil {
		t.Fatalf("read purge mark: %v", err)
	}
	return mark
}

func TestAdminAPI_PurgeRequest_WithoutStorage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t) // no Storage option: the node has no S3
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	const password = "purge-req-pass-1"
	email, accountID := s.newMailAccount(t, "purge-req", password)
	open := s.mustLogin(t, email, password)

	resp, body := s.api.makeRequest(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("purge request on a node without storage: %d %s, want 202", resp.StatusCode, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["purge_requested_at"] == nil {
		t.Errorf("response does not say when the purge was requested: %s", body)
	}

	if s.purgeMark(t, accountID) == nil {
		t.Error("the account is not marked for purging")
	}
	var deleted bool
	if err := s.rdb.QueryRowWithRetry(context.Background(), `SELECT deleted_at IS NOT NULL FROM accounts WHERE id = $1`, accountID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("the account is still in service")
	}
	waitClosed(t, open, "a purge-requested account's open session")
	if _, err := s.login(t, email, password); err == nil {
		t.Error("a purge-requested account can still sign in")
	}

	// The request is visible on the account until the purge is done.
	resp, body = s.api.makeRequest(t, "GET", "/admin/accounts/"+email, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET account: %d %s", resp.StatusCode, body)
	}
	var details map[string]any
	_ = json.Unmarshal(body, &details)
	if details["purge_requested_at"] == nil {
		t.Errorf("GET /admin/accounts/{email} does not show the purge request: %s", body)
	}
}

// Requesting the purge again is fine and keeps the original request time, so the age of
// the oldest pending purge (what an operator alerts on) is not reset by a retry.
func TestAdminAPI_PurgeRequest_Repeated(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t)
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	email, accountID := s.newMailAccount(t, "purge-again", "purge-req-pass-2")

	s.request(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil, http.StatusAccepted)
	first := s.purgeMark(t, accountID)
	if first == nil {
		t.Fatal("not marked after the first request")
	}
	s.request(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil, http.StatusAccepted)
	second := s.purgeMark(t, accountID)
	if second == nil || !second.Equal(*first) {
		t.Errorf("a repeated request changed the request time: %v -> %v", first, second)
	}
}

// A soft-deleted account can be marked too; that is how an operator skips the rest of
// its grace period.
func TestAdminAPI_PurgeRequest_AlreadySoftDeleted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t)
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	email, accountID := s.newMailAccount(t, "purge-soft", "purge-req-pass-3")

	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)
	s.request(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil, http.StatusAccepted)
	if s.purgeMark(t, accountID) == nil {
		t.Error("a soft-deleted account was not marked for purging")
	}
}

func TestAdminAPI_PurgeRequest_UnknownAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t)
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	s.request(t, "DELETE", "/admin/accounts/nobody-"+time.Now().Format("150405.000000")+"@example.com?purge=true", nil, http.StatusNotFound)
}

// Restoring a marked account before the worker gets to it cancels the purge.
func TestAdminAPI_PurgeRequest_RestoreCancels(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t)
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	const password = "purge-req-pass-4"
	email, accountID := s.newMailAccount(t, "purge-restore", password)
	s.addMessage(t, accountID, email, "kept", false)

	s.request(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil, http.StatusAccepted)
	s.request(t, "POST", "/admin/accounts/"+email+"/restore", nil, http.StatusOK)

	if s.purgeMark(t, accountID) != nil {
		t.Error("a restored account is still marked for purging")
	}
	if _, err := s.login(t, email, password); err != nil {
		t.Errorf("a restored account cannot sign in: %v", err)
	}
	if n := s.count(t, "messages", accountID); n != 1 {
		t.Errorf("a restored account lost messages: %d left, want 1", n)
	}
}
