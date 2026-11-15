package userapiproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A login the proxy's rate limit delays waits inside the handler (admitLogin), after
// net/http has set the request's write deadline (writeTimeout, from when it read the
// request headers). A delay as long as it (max_delay and writeTimeout are both 30 s by
// default) ran past it, and the write deadline dropped the answer, so the client got no
// response at all, not even the token of a login with the right password (#1074). The
// read deadline (ReadTimeout) is no part of it: net/http clears it once the body is read.
// The proxy's timeouts are scaled down here, both of them, and the delay outlasts them.
func TestUserAPIProxy_DelayedLoginIsAnsweredPastTheServerTimeouts(t *testing.T) {
	const delay = 400 * time.Millisecond
	limit := rateLimit()
	limit.DelayStartThreshold = 1
	limit.InitialDelay = delay
	limit.MaxDelay = delay
	h, hits := rateLimitedProxy(t, limit)

	ts := httptest.NewUnstartedServer(h)
	ts.Config.ReadTimeout = delay / 4
	ts.Config.WriteTimeout = delay / 4
	ts.Start()
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Timeout = 10 * time.Second

	login := func(password string) (code int, body string, elapsed time.Duration, err error) {
		t.Helper()
		start := time.Now()
		resp, err := client.Post(ts.URL+"/user/auth/login", "application/json",
			strings.NewReader(`{"email":"`+rateLimitKnown+`","password":"`+password+`"}`))
		if err != nil {
			return 0, "", time.Since(start), err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw), time.Since(start), err
	}

	// A wrong password, answered at once: the client's next login waits delay.
	if code, body, _, err := login("wrong-password"); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("setup: first login: status %d %q, error %v; want 401", code, body, err)
	}

	code, body, elapsed, err := login(rateLimitRightPassword)
	if err != nil {
		t.Fatalf("delayed login got no answer after %v: %v", elapsed.Round(time.Millisecond), err)
	}
	if code != http.StatusOK || !strings.Contains(body, `"token"`) {
		t.Fatalf("delayed login with the right password: status %d %q, want 200 with the token", code, body)
	}
	if elapsed < delay {
		t.Errorf("answered after %v, before the %v delay", elapsed, delay)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("%d logins reached the backend, want 2", got)
	}
}
