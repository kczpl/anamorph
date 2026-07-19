package ui

import (
	"time"

	"fyne.io/fyne/v2"

	"anamorph/internal/yubikey"
)

// indirections over the yubikey package so headless tests can fake the
// hardware.
var (
	ykWatch    = yubikey.Watch
	ykSetup    = yubikey.Setup
	ykExchange = yubikey.Exchange
	ykNewPair  = yubikey.NewPair
	ykImport   = yubikey.Import
)

const ykPollInterval = 2 * time.Second

// ykHub multiplexes one hardware watcher to any number of subscribers -
// the presence badge and the panels - so they never race each other for
// exclusive access to the card. all fields are touched from the fyne
// thread only.
type ykHub struct {
	subs map[int]func(yubikey.Info)
	next int // subscription ids
	gen  int // increments per started watcher; orphans stale deliveries
	last yubikey.Info
	seen bool // last holds a delivered state
	stop func()
}

func newYkHub() *ykHub {
	return &ykHub{subs: map[int]func(yubikey.Info){}}
}

// watch subscribes onChange to yubikey state changes, delivered on the
// fyne thread. the first subscriber starts the shared polling watcher and
// the last one's stop ends it; late subscribers immediately receive the
// latest known state. a stopped subscriber is never called again. watch
// and stop must be called from the fyne thread, where all panel code
// already runs.
func (h *ykHub) watch(onChange func(yubikey.Info)) (stop func()) {
	id := h.next
	h.next++
	h.subs[id] = onChange
	if h.seen {
		onChange(h.last)
	}
	if h.stop == nil {
		h.gen++
		gen := h.gen
		h.stop = ykWatch(ykPollInterval, func(info yubikey.Info) {
			fyne.Do(func() {
				if h.stop == nil || gen != h.gen {
					return // delivery from a watcher stopped in the meantime
				}
				h.last, h.seen = info, true
				for _, fn := range h.subs {
					fn(info)
				}
			})
		})
	}
	return func() {
		delete(h.subs, id)
		if len(h.subs) == 0 && h.stop != nil {
			h.stop()
			h.stop = nil
			h.seen = false
		}
	}
}
