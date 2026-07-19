// package stego hides and recovers opaque byte payloads in the least
// significant bits of an image's R, G and B channels. the alpha channel is
// never touched. payloads are length-prefixed so Extract knows where the
// hidden bit stream ends.
package stego

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
)

const (
	channelsPerPixel = 3 // r, g, b - alpha stays untouched
	lengthPrefixLen  = 4
)

var (
	ErrPayloadTooLarge = errors.New("stego: payload does not fit in image")
	ErrCorruptLength   = errors.New("stego: image does not contain a hidden payload")
	errNotCanonical    = errors.New("stego: image must be a tightly packed NRGBA canvas")
)

// capacity returns the maximum payload size in bytes an image of the given
// bounds can hold, after reserving space for the length prefix.
func Capacity(bounds image.Rectangle) int {
	n := bounds.Dx()*bounds.Dy()*channelsPerPixel/8 - lengthPrefixLen
	return max(n, 0)
}

// embed returns a new image with payload hidden in the LSBs of img.
// img must be a tightly packed canvas (Stride == 4*width), as produced by
// image.NewNRGBA; img itself is not mutated.
func Embed(img *image.NRGBA, payload []byte) (*image.NRGBA, error) {
	if err := checkCanonical(img); err != nil {
		return nil, err
	}
	if c := Capacity(img.Bounds()); len(payload) > c {
		return nil, fmt.Errorf("%w: message needs %d bytes, image holds %d", ErrPayloadTooLarge, len(payload), c)
	}

	data := make([]byte, lengthPrefixLen+len(payload))
	binary.BigEndian.PutUint32(data, uint32(len(payload)))
	copy(data[lengthPrefixLen:], payload)

	out := image.NewNRGBA(image.Rect(0, 0, img.Bounds().Dx(), img.Bounds().Dy()))
	copy(out.Pix, img.Pix)
	for i := range len(data) * 8 {
		bit := data[i/8] >> (7 - i%8) & 1
		p := pixByteIndex(i)
		out.Pix[p] = out.Pix[p]&^1 | bit
	}
	return out, nil
}

// extract returns the payload previously hidden by Embed. the embedded
// length prefix is validated against the image capacity before any
// allocation, so arbitrary images fail cleanly with ErrCorruptLength.
func Extract(img *image.NRGBA) ([]byte, error) {
	if err := checkCanonical(img); err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	if bounds.Dx()*bounds.Dy()*channelsPerPixel < lengthPrefixLen*8 {
		return nil, ErrCorruptLength
	}
	n := int(binary.BigEndian.Uint32(readHidden(img, 0, lengthPrefixLen)))
	if n > Capacity(bounds) {
		return nil, ErrCorruptLength
	}
	return readHidden(img, lengthPrefixLen, n), nil
}

// readHidden reassembles count bytes of hidden data starting at byte offset
// off within the embedded bit stream.
func readHidden(img *image.NRGBA, off, count int) []byte {
	out := make([]byte, count)
	for i := range count * 8 {
		p := pixByteIndex(off*8 + i)
		out[i/8] |= (img.Pix[p] & 1) << (7 - i%8)
	}
	return out
}

// pixByteIndex maps a position in the hidden bit stream to the index of the
// Pix byte carrying it: three payload bits per pixel, in the R, G and B
// bytes of each 4-byte NRGBA pixel.
func pixByteIndex(bitPos int) int {
	return bitPos/channelsPerPixel*4 + bitPos%channelsPerPixel
}

func checkCanonical(img *image.NRGBA) error {
	if img.Stride != img.Bounds().Dx()*4 {
		return errNotCanonical
	}
	return nil
}
