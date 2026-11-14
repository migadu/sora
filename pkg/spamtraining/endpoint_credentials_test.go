package spamtraining

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestSubmitTrainingErrorsHideEndpointCredentials: the endpoint may carry the
// service's credentials in its userinfo or query, and a failed submission's error is
// logged by the worker. net/http quotes the URL in its errors with the user name and
// the query, and a URL that does not parse is quoted whole, its reason a piece of it
// (#806).
func TestSubmitTrainingErrorsHideEndpointCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An http-to-https redirect repeats the request URL, query included.
		w.Header().Set("Location", "https://fixture-user:fixture-password@train.example.invalid"+r.URL.RequestURI())
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer redirect.Close()
	redirectHost := strings.TrimPrefix(redirect.URL, "http://")

	for _, tc := range []struct{ name, endpoint string }{
		{"connection refused", "http://fixture-user:fixture-password@" + closedAddr + "/train?api_key=fixture-query-secret"},
		{"unparsable", "https://fixture-user:fixture/password@train.example.invalid/train"},
		{"redirect", "http://fixture-user:fixture-password@" + redirectHost + "/train?api_key=fixture-query-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(&config.SpamTrainingConfig{Enabled: true, Endpoint: tc.endpoint})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			t.Cleanup(c.Close)
			err = c.SubmitTraining(context.Background(), &TrainingRequest{
				Type:      TrainingTypeSpam,
				Message:   "Subject: x\r\n\r\nbody",
				User:      "user@example.com",
				Timestamp: time.Now(),
			})
			if err == nil {
				t.Fatal("SubmitTraining succeeded, want an error")
			}
			if strings.Contains(err.Error(), "fixture") {
				t.Errorf("error quotes the endpoint's credentials: %v", err)
			}
		})
	}
}
