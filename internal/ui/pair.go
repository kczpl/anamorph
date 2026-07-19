package ui

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"

	"anamorph/internal/yubikey"
)

// pairFlow drives the pairing ceremony inside the hide panel's yubikey
// box: one software-generated key is written into two yubikeys in turn,
// making them interchangeable twins - either one opens images locked to
// the pair. the flow is fed by the panel's watcher through ykUpdate and
// dies with the panel's yubikey session.
type pairFlow struct {
	p           *hidePanel
	pair        *yubikey.Pair
	firstDone   bool
	firstSerial uint32
	pending     yubikey.Info // card awaiting the user's replace decision
	busy        bool         // a write is in flight; ignore card events
}

// startPairing enters the ceremony, folding in whatever card is already
// plugged.
func (p *hidePanel) startPairing() {
	if !p.yubikey || p.pairing != nil {
		return
	}
	pair, err := ykNewPair()
	if err != nil {
		setText(p.status, strings.ToUpper(err.Error()), colDanger)
		return
	}
	p.pairing = &pairFlow{p: p, pair: pair}
	p.pairing.update(p.ykInfo)
}

// cancelPairing leaves the ceremony and restores the normal yubikey view.
// a first card that was already written keeps its new key - it is a
// perfectly good solo key, just named as a pair.
func (p *hidePanel) cancelPairing() {
	f := p.pairing
	if f == nil {
		return
	}
	p.pairing = nil
	if f.firstDone {
		setText(p.status, "PAIRING STOPPED - THE FIRST YUBIKEY KEEPS THE NEW KEY", colDim)
	}
	p.ykUpdate(p.ykInfo)
}

// update reacts to a card arriving or leaving during the ceremony.
func (f *pairFlow) update(info yubikey.Info) {
	if f.busy {
		return
	}
	f.pending = yubikey.Info{}
	p := f.p
	switch {
	case info.Status == yubikey.NoCard:
		if f.firstDone {
			f.show(colDim, "NOW PLUG IN THE SECOND YUBIKEY", "")
		} else {
			f.show(colDim, "PAIR: PLUG IN THE FIRST YUBIKEY", "")
		}
		p.setYkActions(p.actCancel)
	case f.firstDone && (info.Serial != 0 && info.Serial == f.firstSerial || info.Name == f.pair.Name):
		// matched by serial or by the pair's unique key name; a zero
		// serial (unreadable) must not make every card look like a twin.
		f.show(colDim, "THIS YUBIKEY IS ALREADY PAIRED - PLUG IN THE OTHER ONE", "")
		p.setYkActions(p.actCancel)
	case info.Status == yubikey.Ready:
		f.pending = info
		f.show(colFg, fmt.Sprintf("YUBIKEY %d ALREADY HAS %s", info.Serial, strings.ToUpper(info.Name)),
			"REPLACING IT MAKES ITS OLD IMAGES UNREADABLE")
		p.setYkActions(p.actReplace, p.actCancel)
	default: // NoKey: plugging a fresh yubikey into a running ceremony is the go-ahead
		f.importTo(info)
	}
}

// confirmReplace overwrites the pending card's anamorph key with the pair
// key, after the user agreed to orphan its old images.
func (f *pairFlow) confirmReplace() {
	if f.pending.Status == yubikey.Ready {
		f.importTo(f.pending)
	}
}

// importTo writes the pair key to the plugged-in card in the background.
func (f *pairFlow) importTo(info yubikey.Info) {
	f.busy = true
	f.pending = yubikey.Info{}
	f.show(colDim, fmt.Sprintf("WRITING KEY TO YUBIKEY %d - KEEP IT PLUGGED IN…", info.Serial), "")
	p := f.p
	p.setYkActions()
	session := p.ykSession
	go func() {
		imported, err := ykImport(f.pair)
		fyne.Do(func() {
			if session == p.ykSession && p.pairing == f {
				f.importDone(imported, err)
			}
		})
	}()
}

// importDone applies the result of a background write.
func (f *pairFlow) importDone(info yubikey.Info, err error) {
	f.busy = false
	p := f.p
	if err != nil {
		f.show(colDanger, strings.ToUpper(err.Error()), "")
		p.setYkActions(p.actCancel)
		return
	}
	if !f.firstDone {
		f.firstDone = true
		f.firstSerial = info.Serial
		f.show(colFg, "FIRST YUBIKEY PAIRED - UNPLUG IT, PLUG IN THE SECOND", "")
		p.setYkActions(p.actCancel)
		return
	}
	p.pairing = nil
	setText(p.status, "PAIRED - EITHER YUBIKEY NOW OPENS THE SAME IMAGES", colFg)
	p.ykUpdate(info)
}

// show writes the ceremony's status line and the dim detail line under it.
func (f *pairFlow) show(c color.Color, line, detail string) {
	setText(f.p.ykStatus, line, c)
	setText(f.p.ykName, detail, colDim)
}
