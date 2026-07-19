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
// programs. the returned stop function ends the polling and is safe to
// call more than once.
func Watch(interval time.Duration, onChange func(Info)) (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var lastCards []string
		var last Info
		for first := true; ; first = false {
			cards, _ := piv.Cards()
			if first || !slices.Equal(cards, lastCards) {
				lastCards = cards
				info := Probe()
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
	if a.Status != b.Status || a.Serial != b.Serial {
		return false
	}
	if (a.Public == nil) != (b.Public == nil) {
		return false
	}
	return a.Public == nil || a.Public.Equal(b.Public)
}
