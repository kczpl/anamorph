package ui

import (
	"image"
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"anamorph/internal/vault"
)

const revealCaption = "DROP A PNG SAVED BY THIS APP"

// revealPanel extracts and decrypts a message from a PNG made by hidePanel.
type revealPanel struct {
	root fyne.CanvasObject
	win  fyne.Window

	loaded    image.Image
	caption   *canvas.Text
	password  *widget.Entry
	revealBtn *outlineButton
	result    *widget.Entry
	resultBox *fyne.Container
	status    *canvas.Text
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

	p.resultBox = container.NewVBox(vgap(26), smallText("MESSAGE", colDim), vgap(8), p.result)
	p.resultBox.Hide()

	p.root = container.NewVBox(
		newDropZone(p.caption, choose),
		vgap(22),
		smallText("PASSWORD - IF ONE WAS SET", colDim),
		vgap(8),
		p.password,
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
	p.loaded = img
	setText(p.status, "", colDim)
	setText(p.caption, strings.ToUpper(name), colFg)
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
	img, password := p.loaded, p.password.Text
	go func() {
		msg, err := vault.Decode(img, password)
		fyne.Do(func() {
			p.revealBtn.SetDisabled(false)
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

// clear wipes the panel back to its pristine state.
func (p *revealPanel) clear() {
	p.loaded = nil
	p.password.SetText("")
	p.result.SetText("")
	p.resultBox.Hide()
	setText(p.caption, revealCaption, colDim)
	setText(p.status, "", colDim)
}
