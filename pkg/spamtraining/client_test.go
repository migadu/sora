package spamtraining

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestSubmitTrainingDoesNotFollowRedirects: a 3xx answer to the training POST is not
// an accepted submission. Followed, a 301/302/303 turns the POST into a body-less GET
// whose 2xx counted as accepted, and a 307/308 replayed the message and the bearer
// token to the Location. The 3xx itself must be reported as a failure naming the
// Location.
func TestSubmitTrainingDoesNotFollowRedirects(t *testing.T) {
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
				if r.URL.Path == "/train" {
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

			c, err := NewClient(&config.SpamTrainingConfig{
				Enabled:   true,
				Endpoint:  srv.URL + "/train",
				AuthToken: "training-token",
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			err = c.SubmitTraining(context.Background(), &TrainingRequest{
				Type:      TrainingTypeSpam,
				Message:   "Subject: x\r\n\r\nbody",
				User:      "user@example.com",
				Timestamp: time.Now(),
			})
			if err == nil {
				t.Fatalf("SubmitTraining = nil after a %d, want an error (a redirect is not an accepted submission); Location was requested %d time(s), %d as POST",
					status, landingHits.Load(), landingPosts.Load())
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

// TestSubmitTrainingAccepts2xx: a 2xx answer to the training POST is still an accepted
// submission, so the redirect check does not reject the normal path.
func TestSubmitTrainingAccepts2xx(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var posts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.Header.Get("Authorization") == "Bearer training-token" {
					posts.Add(1)
				}
				w.WriteHeader(status)
			}))
			defer srv.Close()

			c, err := NewClient(&config.SpamTrainingConfig{
				Enabled:   true,
				Endpoint:  srv.URL + "/train",
				AuthToken: "training-token",
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			if err := c.SubmitTraining(context.Background(), &TrainingRequest{
				Type:      TrainingTypeHam,
				Message:   "Subject: x\r\n\r\nbody",
				User:      "user@example.com",
				Timestamp: time.Now(),
			}); err != nil {
				t.Fatalf("SubmitTraining after a %d = %v, want nil", status, err)
			}
			if n := posts.Load(); n != 1 {
				t.Errorf("endpoint received %d authorized POST(s), want 1", n)
			}
		})
	}
}
