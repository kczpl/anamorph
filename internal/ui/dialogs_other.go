//go:build !darwin

package ui

// non-macOS platforms use Fyne's built-in file dialogs.
const nativeDialogs = false

func nativeChooseFile([]string) (string, error) { return "", nil }
func nativeSaveFile(string) (string, error)     { return "", nil }
