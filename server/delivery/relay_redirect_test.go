package delivery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestHTTPRelayHandlerDoesNotFollowRedirects: a 3xx answer to the relay POST is not a
// delivery. Followed, a 301/302/303 turns the POST into a body-less GET whose 2xx
// counted as delivered (the vacation reply or Sieve redirect was lost), and a 307/308
// replayed the message and the bearer token to the Location. The 3xx itself must be
// reported as a temporary failure that names the Location, so the message stays
// queued while http_url is corrected.
func TestHTTPRelayHandlerDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var landingHits, landingPosts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/deliver" {
					http.Redirect(w, r, "/landing", status)
					return
				}
				landingHits.Add(1)
				if r.Method == http.MethodPost {
					landingPosts.Add(1)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			h := &HTTPRelayHandler{HTTPURL: srv.URL + "/deliver", AuthToken: "relay-token"}
			err := h.sendToHTTPRelay("a@example.com", "b@example.com", []byte("Subject: x\r\n\r\nbody"))
			if err == nil {
				t.Fatalf("sendToHTTPRelay = nil after a %d, want an error (a redirect is not a delivery); Location was requested %d time(s), %d as POST",
					status, landingHits.Load(), landingPosts.Load())
			}
			if IsPermanentError(err) {
				t.Errorf("IsPermanentError(%v) = true, want false (the message must stay queued while http_url is fixed)", err)
			}
			if !strings.Contains(err.Error(), "/landing") {
				t.Errorf("error %q does not name the Location", err)
			}
			if n := landingHits.Load(); n != 0 {
				t.Errorf("Location was requested %d time(s), want 0 (redirects must not be followed)", n)
			}
		})
	}
}
