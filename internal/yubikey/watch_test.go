package yubikey

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

const ykReader = "Yubico YubiKey OTP+FIDO+CCID 00 00"

func waitInfo(t *testing.T, ch chan Info) Info {
	t.Helper()
	select {
	case info := <-ch:
		return info
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery within 2s")
		return Info{}
	}
}

// testWatchRecoversFromLostOpenRace pins the retry: a yubikey that is
// listed but could not be opened - another program held it just then -
// must be probed again until it answers, not stay "absent" until a replug.
func TestWatchRecoversFromLostOpenRace(t *testing.T) {
	var held atomic.Bool
	held.Store(true)
	infos := make(chan Info, 16)
	stop := watch(time.Millisecond,
		func() ([]string, error) { return []string{ykReader}, nil },
		func() Info {
			if held.Load() {
				return Info{Status: NoCard}
			}
			return Info{Status: Ready, Serial: 7, Name: "anamorph 2026-07-19 3f9a1c"}
		},
		func(info Info) { infos <- info })
	defer stop()

	if got := waitInfo(t, infos); got.Status != NoCard {
		t.Fatalf("first delivery status = %d, want NoCard while the card is held", got.Status)
	}
	held.Store(false)
	if got := waitInfo(t, infos); got.Status != Ready {
		t.Fatalf("recovery delivery status = %d, want Ready without a replug", got.Status)
	}
}

// testWatchIdleDoesNotReopenTheCard pins the polite half of the contract:
// with an unchanged reader list and a working key, the card is opened once
// and then left alone.
func TestWatchIdleDoesNotReopenTheCard(t *testing.T) {
	var probes atomic.Int32
	stop := watch(time.Millisecond,
		func() ([]string, error) { return []string{ykReader}, nil },
		func() Info {
			probes.Add(1)
			return Info{Status: Ready, Serial: 7}
		},
		func(Info) {})
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for probes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // dozens of idle ticks
	if got := probes.Load(); got != 1 {
		t.Errorf("probes = %d, want 1 - idle polling must not reopen the card", got)
	}
}

// a reader that is not a yubikey must not trigger the open-retry loop.
func TestWatchDoesNotRetryForeignReaders(t *testing.T) {
	var probes atomic.Int32
	stop := watch(time.Millisecond,
		func() ([]string, error) { return []string{"Generic Smart Card Reader 00"}, nil },
		func() Info {
			probes.Add(1)
			return Info{Status: NoCard}
		},
		func(Info) {})
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for probes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := probes.Load(); got != 1 {
		t.Errorf("probes = %d, want 1 - a foreign reader must not be retried", got)
	}
}

// a transient pc/sc error must read as "nothing changed", not as every
// card disappearing and reappearing.
func TestWatchIgnoresTransientCardListErrors(t *testing.T) {
	var lists, probes atomic.Int32
	stop := watch(time.Millisecond,
		func() ([]string, error) {
			if lists.Add(1) == 1 {
				return []string{ykReader}, nil
			}
			return nil, errors.New("pc/sc hiccup")
		},
		func() Info {
			probes.Add(1)
			return Info{Status: Ready, Serial: 7}
		},
		func(Info) {})

	deadline := time.Now().Add(2 * time.Second)
	for lists.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("probes = %d, want 1 - an errored card list must not look like a change", got)
	}
	stop()
	stop() // stop is documented as safe to call twice
}
