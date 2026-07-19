package ui

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// newTestUI builds the full UI against the headless test driver.
func newTestUI(t *testing.T) (*ui, fyne.Window) {
	t.Helper()
	a := test.NewApp()
	a.Settings().SetTheme(noirTheme{})
	t.Cleanup(func() { test.NewApp() }) // resets the test driver
	w := test.NewWindow(nil)
	t.Cleanup(w.Close)
	u := newUI(w)
	w.SetContent(u.root)
	return u, w
}

// testUIRenders paints both tabs with the software renderer - a smoke test
// that the widget tree constructs and renders. set PREVIEW_DIR to also write
// PNG snapshots for visual inspection.
func TestUIRenders(t *testing.T) {
	u, w := newTestUI(t)
	w.Resize(fyne.NewSize(720, 860))

	dir := os.Getenv("PREVIEW_DIR")
	for i, name := range []string{"hide", "reveal"} {
		u.selectTab(i)
		img := w.Canvas().Capture()
		if img == nil {
			t.Fatalf("tab %s: nothing rendered", name)
		}
		if dir == "" {
			continue
		}
		f, err := os.Create(dir + "/preview-" + name + ".png")
		if err != nil {
			t.Fatalf("create preview: %v", err)
		}
		if err := png.Encode(f, img); err != nil {
			t.Fatalf("encode preview: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close preview: %v", err)
		}
	}
}

// testTabSwitchWipesState guards the core privacy promise: no input, cover
// or revealed message survives a tab change.
func TestTabSwitchWipesState(t *testing.T) {
	u, _ := newTestUI(t)

	u.hide.message.SetText("attack at dawn")
	u.hide.password.SetText("hunter2")
	u.hide.cover = image.NewNRGBA(image.Rect(0, 0, 8, 8))

	u.selectTab(1)
	if u.hide.message.Text != "" || u.hide.password.Text != "" || u.hide.cover != nil {
		t.Error("hide state survived a tab switch")
	}

	u.reveal.password.SetText("pw")
	u.reveal.result.SetText("the secret")
	u.reveal.resultBox.Show()

	u.selectTab(0)
	if u.reveal.password.Text != "" || u.reveal.result.Text != "" {
		t.Error("reveal state survived a tab switch")
	}
	if u.reveal.resultBox.Visible() {
		t.Error("result box still visible after a tab switch")
	}
}

// testReselectingActiveTabKeepsState: clicking the tab you are already on
// must not wipe what you typed.
func TestReselectingActiveTabKeepsState(t *testing.T) {
	u, _ := newTestUI(t)

	u.hide.message.SetText("draft")
	u.selectTab(0)
	if u.hide.message.Text != "draft" {
		t.Error("reselecting the active tab wiped its state")
	}
}

func TestHideLoadReaderShowsCapacity(t *testing.T) {
	u, _ := newTestUI(t)

	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewNRGBA(image.Rect(0, 0, 50, 40))); err != nil {
		t.Fatal(err)
	}
	u.hide.loadReader(&buf, "photo.png")

	if u.hide.cover == nil {
		t.Fatal("cover image not stored")
	}
	// 50*40 px hold 746 payload bytes; minus the 53-byte crypt envelope.
	if want := "PHOTO.PNG - FITS UP TO 693 B"; u.hide.caption.Text != want {
		t.Errorf("caption = %q, want %q", u.hide.caption.Text, want)
	}
}

func TestLoadReaderRejectsGarbage(t *testing.T) {
	u, _ := newTestUI(t)

	u.hide.loadReader(strings.NewReader("not an image"), "junk.png")
	if u.hide.cover != nil {
		t.Error("garbage stored as cover")
	}
	if u.hide.status.Text != "CANNOT READ IMAGE" {
		t.Errorf("status = %q, want CANNOT READ IMAGE", u.hide.status.Text)
	}
}

// testLoadPath covers the drop plumbing: extension filter, unreadable files
// and the happy path via a real PNG written by writePNG.
func TestLoadPath(t *testing.T) {
	test.NewApp()
	t.Cleanup(func() { test.NewApp() })
	status := smallText("", colDim)
	dir := t.TempDir()

	loaded := ""
	onLoad := func(_ io.Reader, name string) { loaded = name }

	loadPath(filepath.Join(dir, "movie.gif"), hideExts, status, onLoad)
	if loaded != "" || status.Text != "UNSUPPORTED FILE TYPE" {
		t.Errorf("gif: loaded=%q status=%q", loaded, status.Text)
	}

	loadPath(filepath.Join(dir, "missing.png"), hideExts, status, onLoad)
	if loaded != "" || status.Text != "CANNOT OPEN FILE" {
		t.Errorf("missing: loaded=%q status=%q", loaded, status.Text)
	}

	path := filepath.Join(dir, "ok.png")
	if err := writePNG(path, image.NewNRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatalf("writePNG: %v", err)
	}
	loadPath(path, hideExts, status, onLoad)
	if loaded != "ok.png" {
		t.Errorf("ok: loaded=%q, want ok.png", loaded)
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{2048, "2.0 KB"},
		{93746, "91.5 KB"},
		{5 << 20, "5.0 MB"},
	}
	for _, tt := range tests {
		if got := formatSize(tt.n); got != tt.want {
			t.Errorf("formatSize(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
