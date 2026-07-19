package ui

import (
	"fmt"
	"image"
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"anamorph/internal/vault"
	"anamorph/internal/yubikey"
)

const (
	revealCaption = "DROP A PNG SAVED BY THIS APP"
	ykPlugCaption = "THIS IMAGE UNLOCKS WITH A YUBIKEY - PLUG IT IN"
)

// revealPanel extracts and decrypts a message from a PNG made by hidePanel.
// the unlock method is read from the hidden payload itself: the panel asks
// for a password or waits for a yubikey, whichever the image needs.
type revealPanel struct {
	root fyne.CanvasObject
	win  fyne.Window

	loaded    image.Image
	payload   []byte // sniffed ahead of time; nil until extraction succeeds
	caption   *canvas.Text
	password  *widget.Entry
	pwBox     *fyne.Container
	ykBox     *fyne.Container
	ykStatus  *canvas.Text
	revealBtn *outlineButton
	result    *widget.Entry
	resultBox *fyne.Container
	status    *canvas.Text
	session   int // invalidates in-flight goroutines on clear or reload
	stopWatch func()
}

func newRevealPanel(win fyne.Window) *revealPanel {
	p := &revealPanel{win: win}
	p.caption = smallText(revealCaption, colDim)
	p.password = widget.NewPasswordEntry()
	p.status = smallText("", colDim)
	p.revealBtn = newOutlineButton("REVEAL MESSAGE", false, p.reveal)
	p.result = newArea()
	var choose *outlineButton
	choose = newOutlineButton("CHOOSE IMAGE", true, func() {
		chooseImage(win, revealExts, choose, p.status, p.loadReader)
	})

	p.pwBox = container.NewVBox(
		smallText("PASSWORD - IF ONE WAS SET", colDim),
		vgap(8),
		p.password,
	)
	p.ykStatus = smallText("", colDim)
	p.ykBox = container.NewVBox(
		smallText("YUBIKEY", colDim),
		vgap(8),
		p.ykStatus,
	)
	p.ykBox.Hide()

	p.resultBox = container.NewVBox(vgap(26), smallText("MESSAGE", colDim), vgap(8), p.result)
	p.resultBox.Hide()

	p.root = container.NewVBox(
		newDropZone(p.caption, choose),
		vgap(22),
		container.NewStack(p.pwBox, p.ykBox),
		vgap(26),
		p.revealBtn,
		vgap(10),
		p.status,
		p.resultBox,
	)
	return p
}

func (p *revealPanel) loadPath(path string) { loadPath(path, revealExts, p.status, p.loadReader) }

func (p *revealPanel) loadReader(r io.Reader, name string) {
	img, _, err := image.Decode(r)
	if err != nil {
		setText(p.status, "CANNOT READ IMAGE", colDanger)
		return
	}
	p.resetLoaded()
	p.loaded = img
	setText(p.status, "", colDim)
	setText(p.caption, strings.ToUpper(name), colFg)
	p.sniff(img)
}

// sniff extracts the payload in the background to learn which unlock
// method the image wants, and reshapes the panel accordingly. extraction
// failures wait for the reveal button - the user may still be mid-drop.
func (p *revealPanel) sniff(img image.Image) {
	session := p.session
	go func() {
		payload, err := vault.Extract(img)
		var needsYk bool
		if err == nil {
			needsYk, err = vault.NeedsYubiKey(payload)
		}
		fyne.Do(func() {
			if session != p.session || err != nil {
				return
			}
			p.payload = payload
			if needsYk {
				p.showYubiKey()
			}
		})
	}()
}

// showYubiKey swaps the password entry for the yubikey status line and
// watches for the right key to show up.
func (p *revealPanel) showYubiKey() {
	p.pwBox.Hide()
	p.ykBox.Show()
	p.password.SetText("")
	setText(p.ykStatus, ykPlugCaption, colDim)
	p.stopWatch = watchYubiKey(func(info yubikey.Info) {
		switch info.Status {
		case yubikey.NoCard:
			setText(p.ykStatus, ykPlugCaption, colDim)
		case yubikey.NoKey:
			setText(p.ykStatus, "THIS YUBIKEY HAS NO ANAMORPH KEY - TRY ANOTHER", colDanger)
		case yubikey.Ready:
			setText(p.ykStatus, fmt.Sprintf("YUBIKEY %d DETECTED", info.Serial), colFg)
		}
	})
}

// reveal decrypts in the background and shows the recovered message.
func (p *revealPanel) reveal() {
	if p.loaded == nil {
		setText(p.status, "CHOOSE AN IMAGE FIRST", colDanger)
		return
	}
	p.revealBtn.SetDisabled(true)
	setText(p.status, "DECRYPTING…", colDim)
	// snapshot on the UI thread: the fields may change while we decrypt.
	img, payload, password := p.loaded, p.payload, p.password.Text
	session := p.session
	go func() {
		msg, err := decode(img, payload, password)
		fyne.Do(func() {
			p.revealBtn.SetDisabled(false)
			if session != p.session {
				return
			}
			if err != nil {
				p.resultBox.Hide()
				setText(p.status, strings.ToUpper(err.Error()), colDanger)
				return
			}
			setText(p.status, "", colDim)
			p.result.SetText(msg)
			p.resultBox.Show()
		})
	}()
}

// decode runs the extract-and-decrypt pipeline off the UI thread, reusing
// the sniffed payload when it is already there.
func decode(img image.Image, payload []byte, password string) (string, error) {
	var err error
	if payload == nil {
		if payload, err = vault.Extract(img); err != nil {
			return "", err
		}
	}
	needsYk, err := vault.NeedsYubiKey(payload)
	if err != nil {
		return "", err
	}
	if needsYk {
		return vault.OpenYubiKey(payload, ykExchange)
	}
	return vault.OpenPassword(payload, password)
}

// clear wipes the panel back to its pristine state.
func (p *revealPanel) clear() {
	p.resetLoaded()
	p.password.SetText("")
	p.result.SetText("")
	p.resultBox.Hide()
	setText(p.caption, revealCaption, colDim)
	setText(p.status, "", colDim)
}

// resetLoaded forgets the current image and its payload and swaps the
// panel back to the password shape.
func (p *revealPanel) resetLoaded() {
	p.session++
	if p.stopWatch != nil {
		p.stopWatch()
		p.stopWatch = nil
	}
	p.loaded = nil
	p.payload = nil
	p.ykBox.Hide()
	p.pwBox.Show()
	setText(p.ykStatus, "", colDim)
}
