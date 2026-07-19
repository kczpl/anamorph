package vault

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"anamorph/internal/crypt"
	"anamorph/internal/stego"
	"anamorph/internal/testkeys"
)

func TestMain(m *testing.M) {
	// keep the suite fast while exercising the real derivation code path.
	crypt.Iterations = 4096
	os.Exit(m.Run())
}

// noisyImage returns a deterministic pseudo-photo, including translucent
// pixels so the alpha-handling path is exercised.
func noisyImage(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	rng := rand.New(rand.NewPCG(7, 42))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.UintN(256))
	}
	return img
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		w, h     int
		message  string
		password string
	}{
		{"short", 64, 64, "meet me at dawn", "hunter2"},
		{"unicode", 64, 64, "zażółć gęślą jaźń ✓ 秘密", "härsło"},
		{"empty message", 32, 32, "", "pw"},
		{"near capacity", 48, 48, strings.Repeat("x", MessageCapacity(image.Rect(0, 0, 48, 48))), "pw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := Encode(noisyImage(tt.w, tt.h), tt.message, tt.password)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := Decode(encoded, tt.password)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got != tt.message {
				t.Errorf("round trip mismatch: got %q, want %q", got, tt.message)
			}
		})
	}
}

// testPNGFileRoundTrip runs the full user journey in memory: encode, write
// an actual PNG file, decode that file's bytes, extract. the cover image
// contains translucent pixels, so this also proves PNG serialization and
// normalization preserve the hidden LSBs exactly.
func TestPNGFileRoundTrip(t *testing.T) {
	const message, password = "the eagle lands at midnight", "correct horse"

	encoded, err := Encode(noisyImage(80, 60), message, password)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var file bytes.Buffer
	if err := png.Encode(&file, encoded); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	decoded, _, err := image.Decode(&file)
	if err != nil {
		t.Fatalf("image.Decode: %v", err)
	}
	got, err := Decode(decoded, password)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != message {
		t.Errorf("got %q, want %q", got, message)
	}
}

// testJPEGCoverRoundTrip uses a JPEG-decoded cover (opaque YCbCr source),
// mirroring the "hide in a photo" flow; the output PNG is fully opaque, so
// png.Encode drops the alpha channel and image.Decode returns *image.RGBA -
// normalization must still recover the exact hidden bits.
func TestJPEGCoverRoundTrip(t *testing.T) {
	const message, password = "z JPEG-a do PNG", "sekret"

	var cover bytes.Buffer
	if err := jpeg.Encode(&cover, noisyImage(100, 100), nil); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	coverImg, _, err := image.Decode(&cover)
	if err != nil {
		t.Fatalf("decode cover: %v", err)
	}

	encoded, err := Encode(coverImg, message, password)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var file bytes.Buffer
	if err := png.Encode(&file, encoded); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	reloaded, _, err := image.Decode(&file)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err := Decode(reloaded, password)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != message {
		t.Errorf("got %q, want %q", got, message)
	}
}

func TestDecodeWrongPassword(t *testing.T) {
	encoded, err := Encode(noisyImage(32, 32), "msg", "right")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := Decode(encoded, "wrong"); !errors.Is(err, crypt.ErrWrongPasswordOrTampered) {
		t.Errorf("got %v, want ErrWrongPasswordOrTampered", err)
	}
}

func TestDecodeCleanImage(t *testing.T) {
	// an image that never went through Encode must fail with a clean error
	// from either layer - never a panic.
	_, err := Decode(noisyImage(32, 32), "pw")
	if !errors.Is(err, stego.ErrCorruptLength) && !errors.Is(err, crypt.ErrNotASecretPayload) {
		t.Errorf("got %v, want ErrCorruptLength or ErrNotASecretPayload", err)
	}
}

func TestEncodeMessageTooLarge(t *testing.T) {
	small := noisyImage(8, 8)
	long := strings.Repeat("x", MessageCapacity(small.Bounds())+1)
	if _, err := Encode(small, long, "pw"); !errors.Is(err, stego.ErrPayloadTooLarge) {
		t.Errorf("got %v, want ErrPayloadTooLarge", err)
	}
}

func TestMessageCapacity(t *testing.T) {
	// the reserved envelope is the yubikey one (102 bytes), the larger of
	// the two, so the shown capacity is honest for either lock method.
	if got, want := MessageCapacity(image.Rect(0, 0, 500, 500)), 93746-102; got != want {
		t.Errorf("MessageCapacity(500x500) = %d, want %d", got, want)
	}
	if got := MessageCapacity(image.Rect(0, 0, 2, 2)); got != 0 {
		t.Errorf("MessageCapacity(2x2) = %d, want 0", got)
	}
}

// testYubiKeyPNGRoundTrip mirrors the full yubikey user journey: seal to a
// key's public half, write a PNG, reload it, sniff the method, decrypt via
// the exchange callback.
func TestYubiKeyPNGRoundTrip(t *testing.T) {
	const message = "the eagle lands at midnight"
	priv, exchange := testkeys.SoftKey(t)

	encoded, err := EncodeYubiKey(noisyImage(80, 60), message, priv.PublicKey())
	if err != nil {
		t.Fatalf("EncodeYubiKey: %v", err)
	}
	var file bytes.Buffer
	if err := png.Encode(&file, encoded); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	reloaded, _, err := image.Decode(&file)
	if err != nil {
		t.Fatalf("image.Decode: %v", err)
	}

	payload, err := Extract(reloaded)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	needs, err := NeedsYubiKey(payload)
	if err != nil || !needs {
		t.Fatalf("NeedsYubiKey = %v, %v, want true, nil", needs, err)
	}
	got, err := OpenYubiKey(payload, exchange)
	if err != nil {
		t.Fatalf("OpenYubiKey: %v", err)
	}
	if got != message {
		t.Errorf("got %q, want %q", got, message)
	}
}

func TestOpenYubiKeyWrongKey(t *testing.T) {
	priv, _ := testkeys.SoftKey(t)
	_, wrongExchange := testkeys.SoftKey(t)

	encoded, err := EncodeYubiKey(noisyImage(32, 32), "msg", priv.PublicKey())
	if err != nil {
		t.Fatalf("EncodeYubiKey: %v", err)
	}
	payload, err := Extract(encoded)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, err := OpenYubiKey(payload, wrongExchange); !errors.Is(err, crypt.ErrWrongYubiKeyOrTampered) {
		t.Errorf("got %v, want ErrWrongYubiKeyOrTampered", err)
	}
}

// testPasswordPayloadSniffsAsPassword pins the sniffing that reveal relies
// on: a password image must never route to the yubikey path.
func TestPasswordPayloadSniffsAsPassword(t *testing.T) {
	encoded, err := Encode(noisyImage(32, 32), "msg", "pw")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	payload, err := Extract(encoded)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	needs, err := NeedsYubiKey(payload)
	if err != nil || needs {
		t.Fatalf("NeedsYubiKey = %v, %v, want false, nil", needs, err)
	}
	got, err := OpenPassword(payload, "pw")
	if err != nil || got != "msg" {
		t.Errorf("OpenPassword = %q, %v, want \"msg\", nil", got, err)
	}
}
