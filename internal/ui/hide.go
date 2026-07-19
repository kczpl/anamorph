package ui

import (
	"fmt"
	"image"
	_ "image/jpeg" // cover images may be JPEG; output is always PNG
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"anamorph/internal/vault"
	"anamorph/internal/yubikey"
)

const hideCaption = "DROP AN IMAGE HERE - PNG OR JPEG"

// hidePanel encrypts a message and embeds it in a chosen cover image. the
// message is locked with either a password or a plugged-in yubikey.
type hidePanel struct {
	root fyne.CanvasObject
	win  fyne.Window

	cover    image.Image
	caption  *canvas.Text
	message  *widget.Entry
	password *widget.Entry
	saveBtn  *outlineButton
	status   *canvas.Text

	// lock method state: the password box or the yubikey status area.
	methodPw  *tab
	methodYk  *tab
	pwBox     *fyne.Container
	ykBox     *fyne.Container
	ykStatus  *canvas.Text
	ykName    *canvas.Text    // key name, or a detail line during pairing
	ykActions *fyne.Container // contextual row of small action links
	yubikey   bool            // true while the yubikey method is selected
	ykInfo    yubikey.Info
	ykSession int // invalidates in-flight yubikey goroutines
	stopWatch func()
	settingUp bool
	pairing   *pairFlow // non-nil while the pairing ceremony runs

	actSetup   *tab
	actPair    *tab
	actReplace *tab
	actCancel  *tab
}

func newHidePanel(win fyne.Window) *hidePanel {
	p := &hidePanel{win: win}
	p.caption = smallText(hideCaption, colDim)
	p.message = newArea()
	p.password = widget.NewPasswordEntry()
	p.status = smallText("", colDim)
	p.saveBtn = newOutlineButton("SAVE IMAGE", false, p.save)
	var choose *outlineButton
	choose = newOutlineButton("CHOOSE IMAGE", true, func() {
		chooseImage(win, hideExts, choose, p.status, p.loadReader)
	})

	p.methodPw = newTab("PASSWORD", func() { p.setMethod(false) })
	p.methodYk = newTab("YUBIKEY", func() { p.setMethod(true) })
	p.methodPw.setActive(true)
	methodRow := container.NewHBox(
		smallText("LOCK WITH", colDim),
		hgap(14),
		p.methodPw, smallText("·", colFaint), p.methodYk,
	)

	p.pwBox = container.NewVBox(
		smallText("OPTIONAL - ENCRYPTS THE MESSAGE", colDim),
		vgap(8),
		p.password,
	)
	p.ykStatus = smallText("", colDim)
	p.ykName = smallText("", colDim)
	p.actSetup = newTab("SET UP THIS KEY", p.ykSetupClick)
	p.actPair = newTab("PAIR TWO KEYS", p.startPairing)
	p.actReplace = newTab("REPLACE", func() {
		if p.pairing != nil {
			p.pairing.confirmReplace()
		}
	})
	p.actCancel = newTab("CANCEL", p.cancelPairing)
	p.ykActions = container.NewHBox()
	p.ykBox = container.NewVBox(vgap(4), p.ykStatus, vgap(8), p.ykName, vgap(12), p.ykActions)
	p.ykBox.Hide()

	p.root = container.NewVBox(
		newDropZone(p.caption, choose),
		vgap(26),
		smallText("MESSAGE", colDim),
		vgap(8),
		p.message,
		vgap(22),
		methodRow,
		vgap(14),
		container.NewStack(p.pwBox, p.ykBox),
		vgap(26),
		p.saveBtn,
		vgap(10),
		p.status,
	)
	return p
}

func (p *hidePanel) loadPath(path string) { loadPath(path, hideExts, p.status, p.loadReader) }

func (p *hidePanel) loadReader(r io.Reader, name string) {
	img, _, err := image.Decode(r)
	if err != nil {
		setText(p.status, "CANNOT READ IMAGE", colDanger)
		return
	}
	p.cover = img
	capacity := vault.MessageCapacity(img.Bounds())
	setText(p.status, "", colDim)
	setText(p.caption, fmt.Sprintf("%s - FITS UP TO %s", strings.ToUpper(name), formatSize(capacity)), colFg)
}

// setMethod switches between the password and yubikey lock methods.
func (p *hidePanel) setMethod(yk bool) {
	if p.yubikey == yk {
		return
	}
	p.yubikey = yk
	p.methodPw.setActive(!yk)
	p.methodYk.setActive(yk)
	if yk {
		p.pwBox.Hide()
		p.ykBox.Show()
		p.password.SetText("")
		p.startYubiKey()
	} else {
		p.stopYubiKey()
		p.ykBox.Hide()
		p.pwBox.Show()
	}
}

// startYubiKey begins watching for a yubikey and drives the status area.
func (p *hidePanel) startYubiKey() {
	p.ykSession++
	setText(p.ykStatus, "PLUG IN A YUBIKEY", colDim)
	setText(p.ykName, "", colDim)
	p.setYkActions(p.actPair)
	p.stopWatch = watchYubiKey(p.ykUpdate)
}

// stopYubiKey ends the watch and forgets everything learned from the card,
// including a half-finished pairing ceremony.
func (p *hidePanel) stopYubiKey() {
	if p.stopWatch != nil {
		p.stopWatch()
		p.stopWatch = nil
	}
	p.ykSession++
	p.settingUp = false
	p.pairing = nil
	p.ykInfo = yubikey.Info{}
	setText(p.ykStatus, "", colDim)
	setText(p.ykName, "", colDim)
	p.setYkActions()
}

// ykUpdate reflects a new yubikey state. a new key offers a choice - set it
// up for this computer alone, or pair two keys - instead of silently
// writing to the card.
func (p *hidePanel) ykUpdate(info yubikey.Info) {
	p.ykInfo = info
	if p.pairing != nil {
		p.pairing.update(info)
		return
	}
	if p.settingUp {
		return
	}
	switch info.Status {
	case yubikey.NoCard:
		setText(p.ykStatus, "PLUG IN A YUBIKEY", colDim)
		setText(p.ykName, "", colDim)
		p.setYkActions(p.actPair)
	case yubikey.NoKey:
		setText(p.ykStatus, fmt.Sprintf("NEW YUBIKEY %d - CHOOSE A SETUP", info.Serial), colFg)
		setText(p.ykName, "SET UP = THIS KEY ALONE · PAIR = TWO KEYS, GIVE ONE AWAY", colDim)
		p.setYkActions(p.actSetup, p.actPair)
	case yubikey.Ready:
		setText(p.ykStatus, fmt.Sprintf("YUBIKEY %d READY", info.Serial), colFg)
		setText(p.ykName, "KEY: "+strings.ToUpper(info.Name), colDim)
		p.setYkActions(p.actPair)
	}
}

// ykSetupClick generates a key on the plugged-in yubikey for this computer
// alone; pairing two yubikeys is the separate ceremony in pair.go.
func (p *hidePanel) ykSetupClick() {
	if p.settingUp || p.pairing != nil || p.ykInfo.Status != yubikey.NoKey {
		return
	}
	p.settingUp = true
	// signing the marker certificate uses the new touch-protected key, so
	// the card blinks for a tap partway through setup.
	setText(p.ykStatus, "SETTING UP - TOUCH THE KEY WHEN IT BLINKS…", colDim)
	setText(p.ykName, "", colDim)
	p.setYkActions()
	session := p.ykSession
	go func() {
		info, err := ykSetup()
		fyne.Do(func() {
			if session != p.ykSession {
				return
			}
			p.settingUp = false
			if err != nil {
				setText(p.ykStatus, strings.ToUpper(err.Error()), colDanger)
				p.setYkActions(p.actSetup, p.actPair)
				return
			}
			p.ykUpdate(info)
		})
	}()
}

// setYkActions swaps the row of small action links under the yubikey
// status for the given tabs.
func (p *hidePanel) setYkActions(tabs ...*tab) {
	objs := make([]fyne.CanvasObject, 0, len(tabs)*2)
	for i, t := range tabs {
		if i > 0 {
			objs = append(objs, smallText("·", colFaint))
		}
		objs = append(objs, t)
	}
	p.ykActions.Objects = objs
	p.ykActions.Refresh()
}

// save encrypts in the background, then hands the result to saveImage,
// which re-enables the button once the save dialog resolves.
func (p *hidePanel) save() {
	if p.cover == nil {
		setText(p.status, "CHOOSE AN IMAGE FIRST", colDanger)
		return
	}
	if p.yubikey && p.pairing != nil {
		setText(p.status, "FINISH PAIRING FIRST", colDanger)
		return
	}
	if p.yubikey && p.ykInfo.Status != yubikey.Ready {
		setText(p.status, "PLUG IN A YUBIKEY FIRST", colDanger)
		return
	}
	p.saveBtn.SetDisabled(true)
	setText(p.status, "ENCRYPTING…", colDim)
	// snapshot on the UI thread: the fields may change while we encrypt.
	cover, message, password := p.cover, p.message.Text, p.password.Text
	useYk, recipient := p.yubikey, p.ykInfo.Public
	go func() {
		var out *image.NRGBA
		var err error
		if useYk {
			out, err = vault.EncodeYubiKey(cover, message, recipient)
		} else {
			out, err = vault.Encode(cover, message, password)
		}
		fyne.Do(func() {
			if err != nil {
				p.saveBtn.SetDisabled(false)
				setText(p.status, strings.ToUpper(err.Error()), colDanger)
				return
			}
			setText(p.status, "", colDim)
			saveImage(p.win, out, p.saveBtn, p.status, p.reset)
		})
	}()
}

// clear wipes the panel back to its pristine state.
func (p *hidePanel) clear() {
	p.cover = nil
	p.message.SetText("")
	p.password.SetText("")
	p.setMethod(false)
	setText(p.caption, hideCaption, colDim)
	setText(p.status, "", colDim)
}

// reset clears the panel for the next message and confirms the save.
func (p *hidePanel) reset(savedName string) {
	p.clear()
	setText(p.status, "SAVED "+strings.ToUpper(savedName), colFg)
}

// formatSize renders a byte count for the capacity caption.
func formatSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
