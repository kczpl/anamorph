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
)

const hideCaption = "DROP AN IMAGE HERE — PNG OR JPEG"

// hidePanel encrypts a message and embeds it in a chosen cover image.
type hidePanel struct {
	root fyne.CanvasObject
	win  fyne.Window

	cover    image.Image
	caption  *canvas.Text
	message  *widget.Entry
	password *widget.Entry
	saveBtn  *outlineButton
	status   *canvas.Text
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

	p.root = container.NewVBox(
		newDropZone(p.caption, choose),
		vgap(26),
		smallText("MESSAGE", colDim),
		vgap(8),
		p.message,
		vgap(22),
		smallText("PASSWORD — OPTIONAL, ENCRYPTS", colDim),
		vgap(8),
		p.password,
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
	setText(p.caption, fmt.Sprintf("%s — FITS UP TO %s", strings.ToUpper(name), formatSize(capacity)), colFg)
}

// save encrypts in the background, then hands the result to saveImage,
// which re-enables the button once the save dialog resolves.
func (p *hidePanel) save() {
	if p.cover == nil {
		setText(p.status, "CHOOSE AN IMAGE FIRST", colDanger)
		return
	}
	p.saveBtn.SetDisabled(true)
	setText(p.status, "ENCRYPTING…", colDim)
	// snapshot on the UI thread: the fields may change while we encrypt.
	cover, message, password := p.cover, p.message.Text, p.password.Text
	go func() {
		out, err := vault.Encode(cover, message, password)
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
