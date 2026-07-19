package ui

import (
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
)

// covers may be PNG or JPEG; hidden messages only survive lossless PNG.
var (
	hideExts   = []string{".png", ".jpg", ".jpeg"}
	revealExts = []string{".png"}
)

// chooseImage opens a file picker - the OS-native panel where available,
// Fyne's dialog otherwise - and hands the picked file to onLoad.
func chooseImage(win fyne.Window, exts []string, btn *outlineButton, status *canvas.Text, onLoad func(io.Reader, string)) {
	if nativeDialogs {
		btn.SetDisabled(true)
		go func() {
			path, err := nativeChooseFile(exts)
			fyne.Do(func() {
				btn.SetDisabled(false)
				if err != nil {
					setText(status, strings.ToUpper(err.Error()), colDanger)
					return
				}
				if path != "" {
					loadPath(path, exts, status, onLoad)
				}
			})
		}()
		return
	}
	d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			setText(status, strings.ToUpper(err.Error()), colDanger)
			return
		}
		if rc == nil {
			return // cancelled
		}
		defer rc.Close()
		onLoad(rc, rc.URI().Name())
	}, win)
	d.SetFilter(storage.NewExtensionFileFilter(exts))
	d.Show()
}

// saveImage asks where to save img - native panel or Fyne dialog - writes it
// as PNG and reports the outcome: onSaved on success, cancellation or the
// error on status otherwise. btn arrives disabled from the encrypt step and
// is re-enabled once the dialog resolves.
func saveImage(win fyne.Window, img *image.NRGBA, btn *outlineButton, status *canvas.Text, onSaved func(name string)) {
	if nativeDialogs {
		go func() {
			path, err := nativeSaveFile("secret.png")
			if err == nil && path != "" {
				err = writePNG(path, img)
			}
			fyne.Do(func() {
				btn.SetDisabled(false)
				switch {
				case err != nil:
					setText(status, strings.ToUpper(err.Error()), colDanger)
				case path == "":
					setText(status, "CANCELLED", colDim)
				default:
					onSaved(filepath.Base(path))
				}
			})
		}()
		return
	}
	d := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		btn.SetDisabled(false)
		switch {
		case err != nil:
			setText(status, strings.ToUpper(err.Error()), colDanger)
		case wc == nil:
			setText(status, "CANCELLED", colDim)
		default:
			name := wc.URI().Name()
			if err := encodePNG(wc, img); err != nil {
				setText(status, strings.ToUpper(err.Error()), colDanger)
				return
			}
			onSaved(name)
		}
	}, win)
	d.SetFileName("secret.png")
	d.SetFilter(storage.NewExtensionFileFilter([]string{".png"}))
	d.Show()
}

// loadPath feeds the file at path to onLoad if its extension is allowed.
func loadPath(path string, exts []string, status *canvas.Text, onLoad func(io.Reader, string)) {
	if !slices.Contains(exts, strings.ToLower(filepath.Ext(path))) {
		setText(status, "UNSUPPORTED FILE TYPE", colDanger)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		setText(status, "CANNOT OPEN FILE", colDanger)
		return
	}
	defer f.Close()
	onLoad(f, filepath.Base(path))
}

func writePNG(path string, img *image.NRGBA) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return encodePNG(f, img)
}

// encodePNG writes img to wc and closes it, keeping whichever error came first.
func encodePNG(wc io.WriteCloser, img *image.NRGBA) error {
	err := png.Encode(wc, img)
	if cerr := wc.Close(); err == nil {
		err = cerr
	}
	return err
}
