package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// textSize is the base font size, shared by the theme and hand-built texts.
const textSize = 13

// the noir palette: near-black background, light gray ink, hairline borders.
var (
	colBg     = color.NRGBA{R: 0x0a, G: 0x0a, B: 0x0a, A: 0xff}
	colFg     = color.NRGBA{R: 0xe6, G: 0xe6, B: 0xe6, A: 0xff}
	colDim    = color.NRGBA{R: 0x8f, G: 0x8f, B: 0x8f, A: 0xff}
	colFaint  = color.NRGBA{R: 0x55, G: 0x55, B: 0x55, A: 0xff}
	colBorder = color.NRGBA{R: 0x3a, G: 0x3a, B: 0x3a, A: 0xff}
	colDanger = color.NRGBA{R: 0xd8, G: 0x6a, B: 0x6a, A: 0xff}
	colOk     = color.NRGBA{R: 0x6a, G: 0xd8, B: 0x8a, A: 0xff}
)

// noirTheme forces a monochrome dark look and monospace type everywhere,
// regardless of the OS theme variant.
type noirTheme struct{}

func (noirTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground, theme.ColorNameInputBackground,
		theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return colBg
	case theme.ColorNameForeground:
		return colFg
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return colBorder
	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return colFaint
	case theme.ColorNamePrimary, theme.ColorNameHyperlink:
		return colFg
	case theme.ColorNameForegroundOnPrimary:
		return colBg
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x14}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x30}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x0d}
	case theme.ColorNameError:
		return colDanger
	case theme.ColorNameScrollBar:
		return colFaint
	default:
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}
}

func (noirTheme) Font(style fyne.TextStyle) fyne.Resource {
	style.Monospace = true
	return theme.DefaultTheme().Font(style)
}

func (noirTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (noirTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return textSize
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 0
	default:
		return theme.DefaultTheme().Size(name)
	}
}
