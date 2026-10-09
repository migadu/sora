package userapi

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/migadu/sora/server/sieveengine"
)

// TestGetCapabilitiesReportsTheCompiledSet pins /user/filters/capabilities to the
// set delivery compiles scripts with. It used to be a hand-written list that claimed
// reject (which the engine does not have) and editheader (which is opt-in), and
// would have missed every extension added since.
func TestGetCapabilitiesReportsTheCompiledSet(t *testing.T) {
	capabilities := func(t *testing.T, configured []string) []string {
		t.Helper()
		s, err := New(nil, ServerOptions{
			Name:            "user-api",
			JWTSecret:       "0123456789abcdef0123456789abcdef",
			SieveExtensions: configured,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		rec := httptest.NewRecorder()
		s.handleGetCapabilities(rec, httptest.NewRequest("GET", "/user/filters/capabilities", nil))
		var body struct {
			Extensions []string `json:"extensions"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.Extensions
	}

	t.Run("default set", func(t *testing.T) {
		got := capabilities(t, nil)
		if !slices.Equal(got, sieveengine.DefaultSieveExtensions) {
			t.Fatalf("got %v, want the default set %v", got, sieveengine.DefaultSieveExtensions)
		}
		for _, ext := range []string{"mime", "foreverypart", "extracttext", "reject", "ereject"} {
			if !slices.Contains(got, ext) {
				t.Errorf("default set lacks %q", ext)
			}
		}
		if slices.Contains(got, "editheader") {
			t.Errorf("claims an extension delivery does not compile by default: %v", got)
		}
	})

	t.Run("all names unknown falls back to the default set, as ManageSieve does", func(t *testing.T) {
		got := capabilities(t, []string{"Fileinto", "vacation "})
		if !slices.Equal(got, sieveengine.DefaultSieveExtensions) {
			t.Fatalf("got %v, want the default set", got)
		}
	})

	t.Run("configured set", func(t *testing.T) {
		// A name the engine does not know is dropped, as ManageSieve drops it.
		configured := []string{"fileinto", "vacation", "editheader", "enotify"}
		want := []string{"fileinto", "vacation", "editheader"}
		if got := capabilities(t, configured); !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}
