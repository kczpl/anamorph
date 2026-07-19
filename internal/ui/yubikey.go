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

// watchYubiKey polls in the background and delivers state changes on the
// fyne thread. the returned stop function also cuts delivery, so a stopped
// watcher never touches the ui again. stop must be called from the fyne
// thread, where all panel code already runs.
func watchYubiKey(onChange func(yubikey.Info)) (stop func()) {
	stopped := false
	stopPoll := ykWatch(ykPollInterval, func(info yubikey.Info) {
		fyne.Do(func() {
			if !stopped {
				onChange(info)
			}
		})
	})
	return func() {
		stopped = true
		stopPoll()
	}
}
