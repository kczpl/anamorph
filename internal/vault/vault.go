// package vault combines encryption and steganography: it hides an
// encrypted message inside an image and recovers it later. any decoded
// image format is accepted; results are meant to be written out as PNG,
// since lossy re-encoding would destroy the hidden bits.
package vault

import (
	"image"
	"image/draw"

	"anamorph/internal/crypt"
	"anamorph/internal/stego"
)

// encode encrypts message with password and hides it in a copy of img.
func Encode(img image.Image, message, password string) (*image.NRGBA, error) {
	payload, err := crypt.Seal(password, message)
	if err != nil {
		return nil, err
	}
	return stego.Embed(normalize(img), payload)
}

// decode extracts and decrypts a message previously hidden by Encode.
func Decode(img image.Image, password string) (string, error) {
	payload, err := stego.Extract(normalize(img))
	if err != nil {
		return "", err
	}
	return crypt.Open(password, payload)
}

// messageCapacity returns how many message bytes fit into an image of the
// given bounds, accounting for the encryption envelope.
func MessageCapacity(bounds image.Rectangle) int {
	return max(stego.Capacity(bounds)-crypt.Overhead, 0)
}

// normalize converts any decoded image — premultiplied, 16-bit, paletted,
// grayscale or YCbCr — into a tightly packed 8-bit non-premultiplied NRGBA
// canvas anchored at the origin, the only representation stego operates on.
// an already-canonical NRGBA passes through untouched: round-tripping it
// through color conversion could disturb the LSBs of translucent pixels.
func normalize(img image.Image) *image.NRGBA {
	if n, ok := img.(*image.NRGBA); ok && n.Rect.Min == (image.Point{}) && n.Stride == n.Rect.Dx()*4 {
		return n
	}
	b := img.Bounds()
	canvas := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(canvas, canvas.Bounds(), img, b.Min, draw.Src)
	return canvas
}
