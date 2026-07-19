package stego

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"math/rand/v2"
	"testing"
)

// testImage returns a canonical NRGBA canvas filled with deterministic noise
// so LSBs are non-trivial.
func testImage(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.UintN(256))
	}
	return img
}

func TestCapacity(t *testing.T) {
	tests := []struct {
		w, h, want int
	}{
		{100, 100, 100*100*3/8 - 4},
		{500, 500, 93746},
		{1, 1, 0}, // 3 bits — not even a length prefix, clamped to 0
		{4, 4, 2}, // 48 bits = 6 bytes - 4 prefix
		{0, 0, 0},
	}
	for _, tt := range tests {
		if got := Capacity(image.Rect(0, 0, tt.w, tt.h)); got != tt.want {
			t.Errorf("Capacity(%dx%d) = %d, want %d", tt.w, tt.h, got, tt.want)
		}
	}
}

func TestEmbedExtractRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		w, h    int
		payload []byte
	}{
		{"empty payload", 10, 10, []byte{}},
		{"single byte", 10, 10, []byte{0xA5}},
		{"text", 64, 64, []byte("hello, world — zażółć gęślą jaźń")},
		{"exactly at capacity", 8, 8, bytes.Repeat([]byte{0xFF}, Capacity(image.Rect(0, 0, 8, 8)))},
		{"all zero bits", 16, 16, make([]byte, 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := testImage(tt.w, tt.h)
			embedded, err := Embed(src, tt.payload)
			if err != nil {
				t.Fatalf("Embed: %v", err)
			}
			got, err := Extract(embedded)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if !bytes.Equal(got, tt.payload) {
				t.Errorf("round trip mismatch: got %q, want %q", got, tt.payload)
			}
		})
	}
}

func TestEmbedDoesNotMutateSource(t *testing.T) {
	src := testImage(16, 16)
	before := bytes.Clone(src.Pix)
	if _, err := Embed(src, []byte("secret")); err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if !bytes.Equal(src.Pix, before) {
		t.Error("Embed mutated its source image")
	}
}

func TestEmbedLeavesAlphaUntouched(t *testing.T) {
	src := testImage(16, 16)
	payload := bytes.Repeat([]byte{0xFF}, Capacity(src.Bounds()))
	embedded, err := Embed(src, payload)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	for i := 3; i < len(src.Pix); i += 4 {
		if embedded.Pix[i] != src.Pix[i] {
			t.Fatalf("alpha byte %d changed: %d -> %d", i, src.Pix[i], embedded.Pix[i])
		}
	}
}

func TestEmbedPayloadTooLarge(t *testing.T) {
	src := testImage(8, 8)
	payload := make([]byte, Capacity(src.Bounds())+1)
	_, err := Embed(src, payload)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("got %v, want ErrPayloadTooLarge", err)
	}
}

func TestExtractCorruptLength(t *testing.T) {
	// hand-craft an image whose embedded length prefix claims far more data
	// than the image can hold: Extract must fail cleanly, not panic or
	// allocate unbounded memory.
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 1<<30)
	for i := range 32 {
		bit := prefix[i/8] >> (7 - i%8) & 1
		p := pixByteIndex(i)
		img.Pix[p] = img.Pix[p]&^1 | bit
	}
	_, err := Extract(img)
	if !errors.Is(err, ErrCorruptLength) {
		t.Errorf("got %v, want ErrCorruptLength", err)
	}
}

func TestExtractImageTooSmallForPrefix(t *testing.T) {
	_, err := Extract(image.NewNRGBA(image.Rect(0, 0, 2, 2)))
	if !errors.Is(err, ErrCorruptLength) {
		t.Errorf("got %v, want ErrCorruptLength", err)
	}
}

func TestNonCanonicalImageRejected(t *testing.T) {
	// a sub-image shares the parent's wider Stride; bit indexing would
	// silently corrupt data, so both Embed and Extract must refuse it.
	parent := testImage(32, 32)
	sub := parent.SubImage(image.Rect(0, 0, 16, 16)).(*image.NRGBA)

	if _, err := Embed(sub, []byte("x")); !errors.Is(err, errNotCanonical) {
		t.Errorf("Embed: got %v, want errNotCanonical", err)
	}
	if _, err := Extract(sub); !errors.Is(err, errNotCanonical) {
		t.Errorf("Extract: got %v, want errNotCanonical", err)
	}
}
