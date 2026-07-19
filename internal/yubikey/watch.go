package yubikey

import (
	"slices"
	"sync"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// watch polls for yubikey arrivals and departures and calls onChange with
// the new state whenever it differs from the last delivered one, starting
// with an immediate initial probe. the card is only opened when the reader
// list changes, so idle polling never locks the applet away from other
// programs. the one exception: a listed yubikey that probed as absent -
// its open lost a race against another program holding the card - is
// retried every tick until it answers, so a lost race cannot leave a
// stale "no yubikey" state behind. the returned stop function ends the
// polling and is safe to call more than once.
func Watch(interval time.Duration, onChange func(Info)) (stop func()) {
	return watch(interval, piv.Cards, Probe, onChange)
}

// watch is Watch with the hardware behind function values, so tests can
// drive the polling loop without a card.
func watch(interval time.Duration, listCards func() ([]string, error), probe func() Info, onChange func(Info)) (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var lastCards []string
		var last Info
		for first := true; ; first = false {
			cards, err := listCards()
			if err != nil {
				cards = lastCards // a transient pc/sc error is not a departure
			}
			retry := last.Status == NoCard && slices.ContainsFunc(cards, isYubiKey)
			if first || retry || !slices.Equal(cards, lastCards) {
				lastCards = cards
				info := probe()
				if first || !info.equal(last) {
					last = info
					onChange(info)
				}
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

func (a Info) equal(b Info) bool {
	if a.Status != b.Status || a.Serial != b.Serial || a.Name != b.Name {
		return false
	}
	if (a.Public == nil) != (b.Public == nil) {
		return false
	}
	return a.Public == nil || a.Public.Equal(b.Public)
}
