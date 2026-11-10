package imapproxy

import (
	"testing"

	"github.com/migadu/sora/config"
)

func TestReloadConfigDebugRequiresRestart(t *testing.T) {
	for _, started := range []bool{false, true} {
		s := &Server{}
		s.settings.Store(&reloadableSettings{debug: started})
		if err := s.ReloadConfig(config.ServerConfig{Type: "imap_proxy", Debug: !started}); err != nil {
			t.Fatal(err)
		}
		if got := s.loadSettings().debug; got != started {
			t.Errorf("debug changed to %v before protocol logger restart (started %v)", got, started)
		}
	}
}
