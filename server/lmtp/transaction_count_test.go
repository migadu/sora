package lmtp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// countingSession is a session with what counting its transactions and logging it out
// touch, on a backend whose gate refuses new transactions or not.
func countingSession(t *testing.T, refusing bool) *LMTPSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &LMTPSession{
		backend: &LMTPServerBackend{
			name:            "test",
			hostname:        "test",
			maintenanceGate: server.NewMaintenanceGate(refusing),
		},
		ctx:       ctx,
		startTime: time.Now(),
	}
	s.Protocol = "LMTP"
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "LMTP", nil)
	return s
}

// go-smtp logs a session out from Server.Close while its MAIL may still be handled. A
// Logout landing while the MAIL is being admitted must leave no transaction counted. It
// left -1 when the gate refused (Logout ended the transaction MAIL had claimed, and the
// refusal took back its own count), a count below the truth that lets --wait call a node
// with a transaction open safe to stop; where the gate admits, it must not leave 1 for
// good.
func TestTransactionCount_LogoutDuringAMail(t *testing.T) {
	for _, refusing := range []bool{true, false} {
		t.Run(fmt.Sprintf("refusing=%v", refusing), func(t *testing.T) {
			s := countingSession(t, refusing)
			loggedOut := make(chan struct{})
			beforeAdmit = func() {
				go func() {
					s.Logout()
					close(loggedOut)
				}()
				select { // lets Logout through, unless it waits for the MAIL to finish
				case <-loggedOut:
				case <-time.After(100 * time.Millisecond):
				}
			}
			t.Cleanup(func() { beforeAdmit = nil })

			if admitted := s.beginTransaction(); admitted == refusing {
				t.Fatalf("beginTransaction = %v with the gate refusing=%v", admitted, refusing)
			}
			<-loggedOut
			if got := s.backend.transactionsOpen.Load(); got != 0 {
				t.Fatalf("transactions open = %d, want 0", got)
			}
		})
	}
}

// RSET on the connection's goroutine (endTransaction) and Logout from Server.Close
// (endSession) end the same transaction: once, and without a data race.
func TestTransactionCount_ResetAndLogoutTogether(t *testing.T) {
	for range 50 {
		s := countingSession(t, false)
		if !s.beginTransaction() {
			t.Fatal("an admitting gate refused the transaction")
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.endTransaction() }()
		go func() { defer wg.Done(); s.endSession() }()
		wg.Wait()
		if got := s.backend.transactionsOpen.Load(); got != 0 {
			t.Fatalf("transactions open = %d, want 0", got)
		}
	}
}

// A MAIL handled after Logout (the same race, the other way round) counts nothing: no end
// would ever take it back, and the node would report a transaction open for good.
func TestTransactionCount_NoneBeginsAfterLogout(t *testing.T) {
	s := countingSession(t, false)
	s.Logout()

	s.beginTransaction()
	if got := s.backend.transactionsOpen.Load(); got != 0 {
		t.Fatalf("transactions open = %d, want 0", got)
	}
	s.endTransaction()
	if got := s.backend.transactionsOpen.Load(); got != 0 {
		t.Fatalf("transactions open = %d after the end, want 0", got)
	}
}
