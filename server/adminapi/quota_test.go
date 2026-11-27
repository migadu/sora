package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStorageQuotaFieldStates(t *testing.T) {
	for _, tc := range []struct {
		body    string
		set     bool
		bytes   int64 // 0 means nil
		wantErr bool
	}{
		{body: `{}`},
		{body: `{"storage_quota": null}`, set: true},
		{body: `{"storage_quota": 1073741824}`, set: true, bytes: 1 << 30},
		{body: `{"storage_quota": "10gb"}`, wantErr: true},
		{body: `{"storage_quota": 1.5}`, wantErr: true},
	} {
		var req StorageQuotaRequest
		err := json.Unmarshal([]byte(tc.body), &req)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: want an error", tc.body)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		f := req.StorageQuota
		if f.Set != tc.set || (tc.bytes == 0) != (f.Bytes == nil) || (f.Bytes != nil && *f.Bytes != tc.bytes) {
			t.Errorf("%s: got Set=%v Bytes=%v", tc.body, f.Set, f.Bytes)
		}
	}
}

func TestStorageQuotaFieldRoundTrips(t *testing.T) {
	n := int64(42)
	for _, tc := range []struct {
		in   CreateAccountRequest
		want string
	}{
		{CreateAccountRequest{Email: "a@example.com"}, `{"email":"a@example.com","password":"","password_hash":""}`},
		{CreateAccountRequest{Email: "a@example.com", StorageQuota: storageQuotaField{Set: true}}, `{"email":"a@example.com","password":"","password_hash":"","storage_quota":null}`},
		{CreateAccountRequest{Email: "a@example.com", StorageQuota: storageQuotaField{Set: true, Bytes: &n}}, `{"email":"a@example.com","password":"","password_hash":"","storage_quota":42}`},
	} {
		b, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != tc.want {
			t.Errorf("Marshal = %s, want %s", b, tc.want)
		}
	}
}

// A PUT without storage_quota must not clear a limit, and a create with a bad one is
// refused before any database work (the bare Server has no database).
func TestQuotaRequestsRefusedBeforeTheDatabase(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
		want    string
	}{
		{"PUT without the member", s.handleSetAccountQuota, "PUT", `{}`, "storage_quota is required"},
		{"PUT with a string", s.handleSetAccountQuota, "PUT", `{"storage_quota":"1gb"}`, "storage_quota must be"},
		{"create with zero", s.handleCreateAccount, "POST", `{"email":"a@example.com","password":"x","storage_quota":0}`, "more than 0"},
		{"create with negative", s.handleCreateAccount, "POST", `{"email":"a@example.com","password":"x","storage_quota":-5}`, "more than 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/admin/accounts/a@example.com/quota", strings.NewReader(tc.body))
			req.SetPathValue("email", "a@example.com")
			rr := httptest.NewRecorder()
			tc.handler(rr, req)
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), tc.want) {
				t.Errorf("got %d %s, want 400 containing %q", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}
