// package ui implements the anamorph desktop interface: a noir, two-tab
// window for hiding encrypted messages inside images and revealing them
// again. all hiding and revealing logic lives in internal/vault; this
// package is presentation and file plumbing only.
package ui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"

	"anamorph/internal/yubikey"
)

// run builds the main window and blocks until the app exits.
func Run() {
	a := app.New()
	a.Settings().SetTheme(noirTheme{})
	w := a.NewWindow("anamorph")
	w.Resize(fyne.NewSize(720, 860))
	u := newUI(w)
	w.SetContent(u.root)
	w.SetOnDropped(u.handleDrop)
	stop := watchYubiKey(u.ykBadgeUpdate)
	defer stop()
	w.ShowAndRun()
}

// ui owns the window layout: header, tab strip and the two panels.
type ui struct {
	root   fyne.CanvasObject
	hide   *hidePanel
	reveal *revealPanel

	tabHide   *tab
	tabReveal *tab
	current   int

	// the presence badge: a green dot and serial shown while a yubikey
	// with an anamorph key is plugged in, invisible otherwise.
	ykBadge  *fyne.Container
	ykSerial *canvas.Text
	tabRow   *fyne.Container // refreshed when the badge toggles, so the row re-lays out
}

func newUI(win fyne.Window) *ui {
	u := &ui{hide: newHidePanel(win), reveal: newRevealPanel(win)}
	u.tabHide = newTab("HIDE", func() { u.selectTab(0) })
	u.tabReveal = newTab("REVEAL", func() { u.selectTab(1) })

	title := canvas.NewText("ANAMORPH", colFg)
	title.TextSize = 28
	title.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	subtitle := smallText("hide messages inside images", colDim)

	dot := smallText("·", colFaint)
	u.ykSerial = smallText("", colDim)
	u.ykBadge = container.NewHBox(smallText("●", colOk), hgap(8), u.ykSerial)
	u.ykBadge.Hide()
	u.tabRow = container.NewHBox(u.tabHide, dot, u.tabReveal, layout.NewSpacer(), u.ykBadge)

	panels := container.NewStack(u.hide.root, u.reveal.root)
	column := container.NewVBox(
		title,
		vgap(2),
		subtitle,
		vgap(28),
		u.tabRow,
		vgap(28),
		panels,
	)
	u.root = container.New(layout.NewCustomPaddedLayout(48, 40, 64, 64), column)
	u.current = -1
	u.selectTab(0)
	return u
}

// selectTab switches panels, wiping all state - secrets never survive a
// tab change.
func (u *ui) selectTab(i int) {
	if i == u.current {
		return
	}
	u.current = i
	u.hide.clear()
	u.reveal.clear()
	u.tabHide.setActive(i == 0)
	u.tabReveal.setActive(i == 1)
	if i == 0 {
		u.reveal.root.Hide()
		u.hide.root.Show()
	} else {
		u.hide.root.Hide()
		u.reveal.root.Show()
	}
}

// ykBadgeUpdate drives the presence badge next to the tabs. it only ever
// lights up for a yubikey that carries an anamorph key; anything less
// shows nothing at all.
func (u *ui) ykBadgeUpdate(info yubikey.Info) {
	if info.Status != yubikey.Ready {
		u.ykBadge.Hide()
	} else {
		setText(u.ykSerial, fmt.Sprintf("YUBIKEY %d", info.Serial), colDim)
		u.ykBadge.Show()
	}
	u.tabRow.Refresh()
}

// handleDrop routes files dropped on the window to the visible panel.
func (u *ui) handleDrop(_ fyne.Position, uris []fyne.URI) {
	if len(uris) == 0 {
		return
	}
	if u.hide.root.Visible() {
		u.hide.loadPath(uris[0].Path())
	} else {
		u.reveal.loadPath(uris[0].Path())
	}
}
