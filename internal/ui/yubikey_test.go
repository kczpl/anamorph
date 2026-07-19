package ui

import (
	"crypto/ecdh"
	"crypto/rand"
	"image"
	mathrand "math/rand/v2"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"anamorph/internal/crypt"
	"anamorph/internal/vault"
	"anamorph/internal/yubikey"
)

func TestMain(m *testing.M) {
	// keep the suite fast while exercising the real derivation code path.
	crypt.Iterations = 4096
	os.Exit(m.Run())
}

// fakeHardware records watcher and setup activity while making sure no
// test ever talks to a real card. the fake setup blocks forever: tests
// assert the synchronous side of the state machine only.
type fakeHardware struct {
	watchStarts, watchStops int
	setupCalls              atomic.Int32
}

func fakeYubiKey(t *testing.T) *fakeHardware {
	t.Helper()
	f := &fakeHardware{}
	origWatch, origSetup, origExchange := ykWatch, ykSetup, ykExchange
	ykWatch = func(time.Duration, func(yubikey.Info)) func() {
		f.watchStarts++
		return func() { f.watchStops++ }
	}
	ykSetup = func() (yubikey.Info, error) {
		f.setupCalls.Add(1)
		select {}
	}
	ykExchange = func(*ecdh.PublicKey) ([]byte, error) {
		t.Error("ykExchange reached real-hardware path")
		return nil, yubikey.ErrNoCard
	}
	t.Cleanup(func() { ykWatch, ykSetup, ykExchange = origWatch, origSetup, origExchange })
	return f
}

func TestHideMethodToggle(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	if !h.pwBox.Visible() || h.ykBox.Visible() {
		t.Fatal("panel must start in password mode")
	}

	h.password.SetText("draft")
	h.setMethod(true)
	if h.pwBox.Visible() || !h.ykBox.Visible() {
		t.Error("yubikey mode did not swap the boxes")
	}
	if h.password.Text != "" {
		t.Error("password survived the switch to yubikey mode")
	}
	if h.ykStatus.Text != "PLUG IN A YUBIKEY" {
		t.Errorf("ykStatus = %q, want PLUG IN A YUBIKEY", h.ykStatus.Text)
	}
	if f.watchStarts != 1 {
		t.Errorf("watchStarts = %d, want 1", f.watchStarts)
	}

	h.setMethod(false)
	if !h.pwBox.Visible() || h.ykBox.Visible() {
		t.Error("password mode did not swap the boxes back")
	}
	if f.watchStops != 1 {
		t.Errorf("watchStops = %d, want 1", f.watchStops)
	}
}

func TestHideYubiKeySaveNeedsKey(t *testing.T) {
	fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.cover = image.NewNRGBA(image.Rect(0, 0, 64, 64))
	h.setMethod(true)
	h.save()
	if h.status.Text != "PLUG IN A YUBIKEY FIRST" {
		t.Errorf("status = %q, want PLUG IN A YUBIKEY FIRST", h.status.Text)
	}
	if h.saveBtn.disabled {
		t.Error("save button left disabled after the guard")
	}
}

func TestHideYubiKeyReady(t *testing.T) {
	fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	priv, _ := softKey(t)
	h.setMethod(true)
	h.ykUpdate(yubikey.Info{Status: yubikey.Ready, Serial: 1234567, Public: priv.PublicKey()})
	if want := "YUBIKEY 1234567 READY - ONLY IT UNLOCKS THIS IMAGE"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	if h.ykInfo.Status != yubikey.Ready {
		t.Error("ready info not stored")
	}
}

func TestHideNewYubiKeyTriggersSetupOnce(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.setMethod(true)
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 7})
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 7})
	if !h.settingUp {
		t.Error("setup not marked as running")
	}
	if want := "NEW YUBIKEY - SETTING IT UP, KEEP IT PLUGGED IN…"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	// the setup goroutine may not have reached the fake yet; give it a
	// moment before insisting it ran exactly once.
	deadline := time.Now().Add(2 * time.Second)
	for f.setupCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := f.setupCalls.Load(); got != 1 {
		t.Errorf("setupCalls = %d, want 1", got)
	}
}

func TestHideClearReturnsToPasswordMode(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.setMethod(true)
	h.clear()
	if h.yubikey || !h.pwBox.Visible() || h.ykBox.Visible() {
		t.Error("clear did not return to password mode")
	}
	if f.watchStops != 1 {
		t.Errorf("watchStops = %d, want 1", f.watchStops)
	}
	if h.ykInfo.Status != yubikey.NoCard {
		t.Error("yubikey info survived clear")
	}
}

func TestRevealYubiKeyShape(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	r := u.reveal

	r.password.SetText("typed")
	r.showYubiKey()
	if r.pwBox.Visible() || !r.ykBox.Visible() {
		t.Error("yubikey shape did not swap the boxes")
	}
	if r.password.Text != "" {
		t.Error("password survived the swap to the yubikey shape")
	}
	if r.ykStatus.Text != ykPlugCaption {
		t.Errorf("ykStatus = %q, want %q", r.ykStatus.Text, ykPlugCaption)
	}
	if f.watchStarts != 1 {
		t.Errorf("watchStarts = %d, want 1", f.watchStarts)
	}

	r.clear()
	if !r.pwBox.Visible() || r.ykBox.Visible() {
		t.Error("clear did not restore the password shape")
	}
	if f.watchStops != 1 {
		t.Errorf("watchStops = %d, want 1", f.watchStops)
	}
}

// softKey stands in for a yubikey: a software P-256 key whose ECDH half
// exercises the exact same code path the hardware provides.
func softKey(t *testing.T) (*ecdh.PrivateKey, func(*ecdh.PublicKey) ([]byte, error)) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, func(ephemeral *ecdh.PublicKey) ([]byte, error) {
		return priv.ECDH(ephemeral)
	}
}

func noisyImage(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	rng := mathrand.New(mathrand.NewPCG(7, 42))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.UintN(256))
	}
	return img
}

// testDecodeRoutesByPayload pins the reveal pipeline's dispatch: password
// images decrypt with the typed password, yubikey images via the exchange.
func TestDecodeRoutesByPayload(t *testing.T) {
	fakeYubiKey(t)
	priv, exchange := softKey(t)
	origExchange := ykExchange
	ykExchange = exchange
	t.Cleanup(func() { ykExchange = origExchange })

	pwImg, err := vault.Encode(noisyImage(48, 48), "password secret", "pw")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	ykImg, err := vault.EncodeYubiKey(noisyImage(48, 48), "yubikey secret", priv.PublicKey())
	if err != nil {
		t.Fatalf("EncodeYubiKey: %v", err)
	}

	if got, err := decode(pwImg, nil, "pw"); err != nil || got != "password secret" {
		t.Errorf("password image: got %q, %v", got, err)
	}
	if got, err := decode(ykImg, nil, "ignored"); err != nil || got != "yubikey secret" {
		t.Errorf("yubikey image: got %q, %v", got, err)
	}
	if _, err := decode(pwImg, nil, "wrong"); err == nil {
		t.Error("wrong password succeeded")
	}
}
