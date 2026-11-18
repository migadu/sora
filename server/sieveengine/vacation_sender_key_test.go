package sieveengine

import (
	"context"
	"testing"
	"time"
)

// recordingVacationOracle records the sender every vacation check and claim is keyed by.
type recordingVacationOracle struct{ checked, claimed []string }

func (o *recordingVacationOracle) IsVacationResponseAllowed(_ context.Context, _ int64, sender, _ string, _ time.Duration) (bool, error) {
	o.checked = append(o.checked, sender)
	return true, nil
}

func (o *recordingVacationOracle) ClaimVacationResponse(_ context.Context, _ int64, sender, _ string, _ time.Duration) (bool, error) {
	o.claimed = append(o.claimed, sender)
	return true, nil
}

// The envelope sender keeps the case of its local part (RFC 5321 §2.4, #2101), but the
// :days window of RFC 5230 §4.2 is kept per sender compared case-insensitively, as it
// was when the sender was lower-cased on the way in: John.Doe and john.doe are one
// correspondent here, and the rows already stored stay the keys they were.
func TestVacationKeyedByLowerCasedSender(t *testing.T) {
	compiled, err := CompileScript(`require "vacation"; vacation :days 1 "Away.";`, EffectiveExtensions(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ from, key string }{
		{"John.Doe@example.com", "john.doe@example.com"},
		{`"John Doe"@example.com`, `"john doe"@example.com`},
	} {
		oracle := &recordingVacationOracle{}
		result, err := compiled.NewExecutor(1, oracle, nil, 0, 0, 0).Evaluate(context.Background(), Context{
			EnvelopeFrom: tt.from,
			EnvelopeTo:   "jane@example.com",
			Header:       map[string][]string{"to": {"jane@example.com"}},
			Message:      bodyOnly("hello"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Vacation == nil || result.Vacation.ClaimResponse == nil {
			t.Fatalf("from %s: no vacation reply", tt.from)
		}
		if _, err := result.Vacation.ClaimResponse(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(oracle.checked) != 1 || oracle.checked[0] != tt.key || len(oracle.claimed) != 1 || oracle.claimed[0] != tt.key {
			t.Errorf("from %s: checked %q, claimed %q, want both keyed %q", tt.from, oracle.checked, oracle.claimed, tt.key)
		}
	}
}

// A sender that is one of the script's own :addresses gets no reply, whatever the case
// of either (#2101): the sender now keeps the case it was sent with, so go-sieve must
// compare it with :addresses without case (v1.5.5, migadu/go-sieve#61), and
// Me@example.com is still the user's own me@example.com.
func TestVacationOwnAddressesIgnoreCase(t *testing.T) {
	for _, tt := range []struct {
		from      string
		addresses string
		reply     bool
	}{
		{"Me@example.com", `["me@example.com"]`, false},
		{"me@example.com", `["ME@Example.COM"]`, false},
		{`"Me Too"@example.com`, `["\"me too\"@example.com"]`, false},
		{"someone@example.com", `["me@example.com"]`, true},
	} {
		compiled, err := CompileScript(`require "vacation"; vacation :days 1 :addresses `+tt.addresses+` "Away.";`, EffectiveExtensions(nil))
		if err != nil {
			t.Fatal(err)
		}
		oracle := &recordingVacationOracle{}
		result, err := compiled.NewExecutor(1, oracle, nil, 0, 0, 0).Evaluate(context.Background(), Context{
			EnvelopeFrom: tt.from,
			EnvelopeTo:   "jane@example.com",
			Header:       map[string][]string{"to": {"jane@example.com"}},
			Message:      bodyOnly("hello"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := result.Vacation != nil; got != tt.reply {
			t.Errorf("from %s, :addresses %s: reply %v, want %v", tt.from, tt.addresses, got, tt.reply)
		}
	}
}
