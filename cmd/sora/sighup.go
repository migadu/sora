package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/migadu/sora/logger"
)

// sighupHandler takes SIGHUP for the whole life of the process. SIGHUP's default action
// terminates it, and start-up (the migrations, the wait for other nodes' migrations, S3,
// the cluster) can take minutes, during which a log rotation or a `systemctl reload`
// must not kill sora. Every SIGHUP reopens the log file at once. The configuration
// reload needs the running servers, so one asked for before start is held and runs
// once start hands over the reload, however many SIGHUPs came; main does that once the
// servers have registered for reload (startWhenServersRegistered).
type sighupHandler struct {
	signals chan os.Signal

	mu      sync.Mutex
	reload  func() // nil until start
	pending bool   // a SIGHUP came before start
}

// listenForSIGHUP takes SIGHUP from now on. main calls it before any start-up work.
func listenForSIGHUP() *sighupHandler {
	h := &sighupHandler{signals: make(chan os.Signal, 1)}
	signal.Notify(h.signals, syscall.SIGHUP)
	go func() {
		for range h.signals {
			h.received()
		}
	}()
	return h
}

func (h *sighupHandler) received() {
	// newsyslog sends SIGHUP after rotating the log file: reopen it first, so what
	// follows is logged into the new file.
	if err := logger.Reopen(); err != nil {
		logger.Error("SIGHUP: log file not reopened", "error", err)
	}
	h.mu.Lock()
	reload := h.reload
	if reload == nil {
		h.pending = true
	}
	h.mu.Unlock()
	if reload == nil {
		logger.Info("SIGHUP received during start-up - log file reopened; the configuration is reloaded once the servers have started")
		return
	}
	reload()
}

// start makes every SIGHUP from now on call reload, and reloads once if a SIGHUP came
// during start-up. That reload runs on the signal goroutine, as every other does, so
// two never overlap.
func (h *sighupHandler) start(reload func()) {
	h.mu.Lock()
	h.reload = reload
	pending := h.pending
	h.pending = false
	h.mu.Unlock()
	if pending {
		select {
		case h.signals <- syscall.SIGHUP:
		default: // a SIGHUP is already queued, and it reloads
		}
	}
}

// startWhenServersRegistered hands h the reload once every server that takes one has
// registered for it (deps.serversRegistered). A reload run while one is still starting
// would pass it over: the settings its ReloadConfig applies would be reported as
// needing a restart, and it would keep the ones it started with, a rotated api_key or
// jwt_secret among them. Until then a SIGHUP only reopens the log file, as during the
// rest of start-up. Nothing is handed over once ctx is done.
func (h *sighupHandler) startWhenServersRegistered(ctx context.Context, deps *serverDependencies, reload func()) {
	go func() {
		select {
		case <-deps.serversRegistered():
			h.start(reload)
		case <-ctx.Done():
		}
	}()
}
