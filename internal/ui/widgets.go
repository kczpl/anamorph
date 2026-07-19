package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// smallText returns a monospace canvas.Text at the app's base size.
func smallText(s string, c color.Color) *canvas.Text {
	t := canvas.NewText(s, c)
	t.TextSize = textSize
	t.TextStyle = fyne.TextStyle{Monospace: true}
	return t
}

// setText updates a canvas.Text in place; used for statuses and captions.
func setText(t *canvas.Text, s string, c color.Color) {
	t.Text = s
	t.Color = c
	t.Refresh()
}

// vgap is a fixed-height vertical spacer.
func vgap(h float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(0, h))
	return r
}

// hline is a full-width horizontal rule.
func hline(c color.Color) fyne.CanvasObject {
	r := canvas.NewRectangle(c)
	r.SetMinSize(fyne.NewSize(0, 1))
	return r
}

// newArea returns the multiline entry used for the message and the result.
func newArea() *widget.Entry {
	e := widget.NewMultiLineEntry()
	e.Wrapping = fyne.TextWrapWord
	e.SetMinRowsVisible(7)
	return e
}

// newDropZone frames a caption and a chooser button in a hairline box the
// user can also drop files onto (drops are wired at the window level).
func newDropZone(caption *canvas.Text, choose fyne.CanvasObject) fyne.CanvasObject {
	border := canvas.NewRectangle(color.Transparent)
	border.StrokeColor = colBorder
	border.StrokeWidth = 1
	border.SetMinSize(fyne.NewSize(0, 200))
	inner := container.NewVBox(
		layout.NewSpacer(),
		container.NewCenter(caption),
		vgap(16),
		container.NewCenter(choose),
		layout.NewSpacer(),
	)
	return container.NewStack(border, inner)
}

// outlineButton is a flat, hairline-bordered button. bright buttons rest in
// the foreground color; others rest dim and light up on hover.
type outlineButton struct {
	widget.BaseWidget
	text     *canvas.Text
	box      *canvas.Rectangle
	onTapped func()
	bright   bool
	hovered  bool
	disabled bool
}

func newOutlineButton(label string, bright bool, tapped func()) *outlineButton {
	b := &outlineButton{onTapped: tapped, bright: bright}
	b.text = smallText(label, colFg)
	b.box = canvas.NewRectangle(color.Transparent)
	b.box.StrokeWidth = 1
	b.applyStyle()
	b.ExtendBaseWidget(b)
	return b
}

func (b *outlineButton) applyStyle() {
	ink, stroke := colDim, colBorder
	if b.bright || b.hovered {
		ink, stroke = colFg, colFg
	}
	if b.disabled {
		ink, stroke = colFaint, colBorder
	}
	b.text.Color = ink
	b.box.StrokeColor = stroke
	b.text.Refresh()
	b.box.Refresh()
}

func (b *outlineButton) SetDisabled(disabled bool) {
	b.disabled = disabled
	b.applyStyle()
}

func (b *outlineButton) Tapped(*fyne.PointEvent) {
	if !b.disabled && b.onTapped != nil {
		b.onTapped()
	}
}

func (b *outlineButton) MouseIn(*desktop.MouseEvent)    { b.hovered = true; b.applyStyle() }
func (b *outlineButton) MouseMoved(*desktop.MouseEvent) {}
func (b *outlineButton) MouseOut()                      { b.hovered = false; b.applyStyle() }

func (b *outlineButton) Cursor() desktop.Cursor {
	if b.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

func (b *outlineButton) CreateRenderer() fyne.WidgetRenderer {
	return &outlineButtonRenderer{b: b}
}

type outlineButtonRenderer struct{ b *outlineButton }

func (r *outlineButtonRenderer) Layout(size fyne.Size) {
	r.b.box.Resize(size)
	t := r.b.text.MinSize()
	r.b.text.Resize(t)
	r.b.text.Move(fyne.NewPos((size.Width-t.Width)/2, (size.Height-t.Height)/2))
}

func (r *outlineButtonRenderer) MinSize() fyne.Size {
	t := r.b.text.MinSize()
	return fyne.NewSize(t.Width+48, t.Height+22)
}

func (r *outlineButtonRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.b.box, r.b.text}
}

func (r *outlineButtonRenderer) Refresh() { canvas.Refresh(r.b) }
func (r *outlineButtonRenderer) Destroy() {}

// tab is a plain text tab: dim when inactive, underlined ink when active.
type tab struct {
	widget.BaseWidget
	text     *canvas.Text
	line     *canvas.Rectangle
	onTapped func()
}

func newTab(label string, tapped func()) *tab {
	t := &tab{onTapped: tapped}
	t.text = smallText(label, colDim)
	t.text.TextSize = textSize + 1
	t.line = canvas.NewRectangle(color.Transparent)
	t.ExtendBaseWidget(t)
	return t
}

func (t *tab) setActive(active bool) {
	if active {
		t.text.Color = colFg
		t.line.FillColor = colFg
	} else {
		t.text.Color = colDim
		t.line.FillColor = color.Transparent
	}
	t.text.Refresh()
	t.line.Refresh()
}

func (t *tab) Tapped(*fyne.PointEvent) {
	if t.onTapped != nil {
		t.onTapped()
	}
}

func (t *tab) Cursor() desktop.Cursor { return desktop.PointerCursor }

func (t *tab) CreateRenderer() fyne.WidgetRenderer {
	return &tabRenderer{t: t}
}

type tabRenderer struct{ t *tab }

func (r *tabRenderer) Layout(fyne.Size) {
	ts := r.t.text.MinSize()
	r.t.text.Resize(ts)
	r.t.text.Move(fyne.NewPos(0, 0))
	r.t.line.Resize(fyne.NewSize(ts.Width, 2))
	r.t.line.Move(fyne.NewPos(0, ts.Height+3))
}

func (r *tabRenderer) MinSize() fyne.Size {
	ts := r.t.text.MinSize()
	return fyne.NewSize(ts.Width, ts.Height+5)
}

func (r *tabRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.t.text, r.t.line}
}

func (r *tabRenderer) Refresh() { canvas.Refresh(r.t) }
func (r *tabRenderer) Destroy() {}
