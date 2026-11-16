package delivery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

func TestHTTPRelayMaskLeavesPaddedRequestQueryUntouched(t *testing.T) {
	const raw = "Zml4dHVyZQ==&sig=fixture%3D%3D&debug="
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.RawQuery
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	h := &HTTPRelayHandler{HTTPURL: srv.URL + "/send?" + raw}
	if strings.Contains(config.MaskEndpointURL(h.HTTPURL), "Zml4dHVyZQ") {
		t.Fatal("dummy padded credential remained in displayed endpoint")
	}
	if err := h.SendToExternalRelay("sender@example.invalid", "recipient@example.invalid", []byte("Subject: fixture\r\n\r\nbody")); err != nil {
		t.Fatal("loopback relay request failed")
	}
	if actual := <-got; actual != raw {
		t.Fatal("masking changed the dummy query sent over HTTP")
	}
	if h.HTTPURL != srv.URL+"/send?"+raw {
		t.Fatal("masking changed the configured endpoint")
	}
}
