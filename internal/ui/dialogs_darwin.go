//go:build darwin

package ui

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS gets real native file panels, driven through the system osascript
// binary — no extra dependencies. other platforms fall back to Fyne's
// built-in dialogs.
const nativeDialogs = true

// nativeChooseFile shows the native open panel restricted to the given
// extensions. it returns "" with a nil error when the user cancels.
func nativeChooseFile(exts []string) (string, error) {
	script := fmt.Sprintf("POSIX path of (choose file with prompt \"Choose an image\" of type %s)", utiList(exts))
	return runPanel(script)
}

// nativeSaveFile shows the native save panel and returns the chosen path,
// forced to a .png extension. it returns "" with a nil error on cancel.
func nativeSaveFile(defaultName string) (string, error) {
	script := fmt.Sprintf("POSIX path of (choose file name with prompt \"Save image\" default name %q)", defaultName)
	path, err := runPanel(script)
	if err != nil || path == "" {
		return path, err
	}
	if !strings.EqualFold(filepath.Ext(path), ".png") {
		path += ".png"
	}
	return path, nil
}

func runPanel(script string) (string, error) {
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && strings.Contains(string(exit.Stderr), "-128") {
			return "", nil // user cancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// utiList renders the AppleScript type filter for a set of extensions.
func utiList(exts []string) string {
	var png, jpeg bool
	for _, e := range exts {
		switch e {
		case ".png":
			png = true
		case ".jpg", ".jpeg":
			jpeg = true
		}
	}
	var utis []string
	if png {
		utis = append(utis, `"public.png"`)
	}
	if jpeg {
		utis = append(utis, `"public.jpeg"`)
	}
	return "{" + strings.Join(utis, ", ") + "}"
}
