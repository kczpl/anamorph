package ui

import (
	"crypto/ecdh"
	"image"
	mathrand "math/rand/v2"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"anamorph/internal/crypt"
	"anamorph/internal/testkeys"
	"anamorph/internal/vault"
	"anamorph/internal/yubikey"
)

func TestMain(m *testing.M) {
	// keep the suite fast while exercising the real derivation code path.
	crypt.Iterations = 4096
	os.Exit(m.Run())
}

// fakeHardware records watcher, setup and import activity while making
// sure no test ever talks to a real card. the fake setup and import block
// forever: tests assert the synchronous side of the state machine only and
// feed results in by calling completion methods directly.
type fakeHardware struct {
	watchStarts, watchStops int
	setupCalls              atomic.Int32
	importCalls             atomic.Int32
}

func fakeYubiKey(t *testing.T) *fakeHardware {
	t.Helper()
	f := &fakeHardware{}
	origWatch, origSetup, origExchange := ykWatch, ykSetup, ykExchange
	origImport := ykImport
	ykWatch = func(time.Duration, func(yubikey.Info)) func() {
		f.watchStarts++
		return func() { f.watchStops++ }
	}
	ykSetup = func() (yubikey.Info, error) {
		f.setupCalls.Add(1)
		select {}
	}
	ykImport = func(*yubikey.Pair) (yubikey.Info, error) {
		f.importCalls.Add(1)
		select {}
	}
	ykExchange = func(*ecdh.PublicKey) ([]byte, error) {
		t.Error("ykExchange reached real-hardware path")
		return nil, yubikey.ErrNoCard
	}
	t.Cleanup(func() {
		ykWatch, ykSetup, ykExchange = origWatch, origSetup, origExchange
		ykImport = origImport
	})
	return f
}

// waitCalls blocks until the counter reaches want or the deadline passes;
// the fakes record the call before blocking, so this is the only
// asynchrony tests have to absorb.
func waitCalls(t *testing.T, c *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.Load() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := c.Load(); got != want {
		t.Fatalf("calls = %d, want %d", got, want)
	}
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

	priv, _ := testkeys.SoftKey(t)
	h.setMethod(true)
	h.ykUpdate(yubikey.Info{Status: yubikey.Ready, Serial: 1234567, Public: priv.PublicKey(), Name: "anamorph 2026-07-19 3f9a1c"})
	if want := "YUBIKEY 1234567 READY"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	if want := "KEY: ANAMORPH 2026-07-19 3F9A1C"; h.ykName.Text != want {
		t.Errorf("ykName = %q, want %q", h.ykName.Text, want)
	}
	if h.ykInfo.Status != yubikey.Ready {
		t.Error("ready info not stored")
	}
}

// testHideNewYubiKeyOffersChoices pins the explicit-consent setup: a fresh
// yubikey must never be written to until the user picks solo setup or
// pairing.
func TestHideNewYubiKeyOffersChoices(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.setMethod(true)
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 7})
	if want := "NEW YUBIKEY 7 - CHOOSE A SETUP"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	if got := f.setupCalls.Load(); got != 0 {
		t.Fatalf("setup ran without the user's choice: setupCalls = %d", got)
	}

	h.ykSetupClick()
	if !h.settingUp {
		t.Error("setup not marked as running")
	}
	if want := "SETTING UP - TOUCH THE KEY WHEN IT BLINKS…"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	waitCalls(t, &f.setupCalls, 1)

	// a second click and a repeated watcher event must not start it again.
	h.ykSetupClick()
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 7})
	if got := f.setupCalls.Load(); got != 1 {
		t.Errorf("setupCalls = %d, want 1", got)
	}
}

// testHidePairCeremony walks the whole happy path: two fresh yubikeys
// plugged in turn, each written once, ending back in the normal ready view.
func TestHidePairCeremony(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide
	priv, _ := testkeys.SoftKey(t)

	h.setMethod(true)
	h.startPairing()
	if h.pairing == nil {
		t.Fatal("pairing did not start")
	}
	if want := "PAIR: PLUG IN THE FIRST YUBIKEY"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	pairName := h.pairing.pair.Name

	// first fresh card: plugging it in during the ceremony is the consent.
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 111})
	if want := "WRITING KEY TO YUBIKEY 111 - KEEP IT PLUGGED IN…"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	waitCalls(t, &f.importCalls, 1)
	h.pairing.importDone(yubikey.Info{Status: yubikey.Ready, Serial: 111, Public: priv.PublicKey(), Name: pairName}, nil)
	if want := "FIRST YUBIKEY PAIRED - UNPLUG IT, PLUG IN THE SECOND"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}

	// replugging the first card must be recognized, not written again.
	h.ykUpdate(yubikey.Info{Status: yubikey.NoCard})
	if want := "NOW PLUG IN THE SECOND YUBIKEY"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	h.ykUpdate(yubikey.Info{Status: yubikey.Ready, Serial: 111, Public: priv.PublicKey(), Name: pairName})
	if want := "THIS YUBIKEY IS ALREADY PAIRED - PLUG IN THE OTHER ONE"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}

	// the second fresh card finishes the ceremony.
	h.ykUpdate(yubikey.Info{Status: yubikey.NoCard})
	h.ykUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 222})
	waitCalls(t, &f.importCalls, 2)
	h.pairing.importDone(yubikey.Info{Status: yubikey.Ready, Serial: 222, Public: priv.PublicKey(), Name: pairName}, nil)
	if h.pairing != nil {
		t.Error("ceremony did not end after the second card")
	}
	if want := "PAIRED - EITHER YUBIKEY NOW OPENS THE SAME IMAGES"; h.status.Text != want {
		t.Errorf("status = %q, want %q", h.status.Text, want)
	}
	if want := "YUBIKEY 222 READY"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
}

// testHidePairReplaceConfirm: a card that already carries an anamorph key
// is only overwritten after the user explicitly agrees.
func TestHidePairReplaceConfirm(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide
	priv, _ := testkeys.SoftKey(t)

	h.setMethod(true)
	h.startPairing()
	h.ykUpdate(yubikey.Info{Status: yubikey.Ready, Serial: 999, Public: priv.PublicKey(), Name: "anamorph 2026-01-01 aaaaaa"})
	if want := "YUBIKEY 999 ALREADY HAS ANAMORPH 2026-01-01 AAAAAA"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}
	if want := "REPLACING IT MAKES ITS OLD IMAGES UNREADABLE"; h.ykName.Text != want {
		t.Errorf("ykName = %q, want %q", h.ykName.Text, want)
	}
	if got := f.importCalls.Load(); got != 0 {
		t.Fatalf("card written without confirmation: importCalls = %d", got)
	}
	h.pairing.confirmReplace()
	waitCalls(t, &f.importCalls, 1)
}

func TestHidePairCancel(t *testing.T) {
	fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.setMethod(true)
	h.startPairing()
	h.cancelPairing()
	if h.pairing != nil {
		t.Error("cancel did not end the ceremony")
	}
	if want := "PLUG IN A YUBIKEY"; h.ykStatus.Text != want {
		t.Errorf("ykStatus = %q, want %q", h.ykStatus.Text, want)
	}

	// cancelling after the first card was written must say the key stays.
	h.startPairing()
	h.pairing.firstDone = true
	h.cancelPairing()
	if want := "PAIRING STOPPED - THE FIRST YUBIKEY KEEPS THE NEW KEY"; h.status.Text != want {
		t.Errorf("status = %q, want %q", h.status.Text, want)
	}
}

func TestHideSaveBlockedDuringPairing(t *testing.T) {
	fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.cover = image.NewNRGBA(image.Rect(0, 0, 64, 64))
	h.setMethod(true)
	h.startPairing()
	h.save()
	if want := "FINISH PAIRING FIRST"; h.status.Text != want {
		t.Errorf("status = %q, want %q", h.status.Text, want)
	}
}

func TestHideClearReturnsToPasswordMode(t *testing.T) {
	f := fakeYubiKey(t)
	u, _ := newTestUI(t)
	h := u.hide

	h.setMethod(true)
	h.startPairing()
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
	if h.pairing != nil {
		t.Error("pairing ceremony survived clear")
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

// testYubiKeyBadge pins the header presence dot: visible only while a
// yubikey carrying an anamorph key is plugged in.
func TestYubiKeyBadge(t *testing.T) {
	fakeYubiKey(t)
	u, _ := newTestUI(t)

	if u.ykBadge.Visible() {
		t.Error("badge visible before any yubikey was seen")
	}
	priv, _ := testkeys.SoftKey(t)
	u.ykBadgeUpdate(yubikey.Info{Status: yubikey.Ready, Serial: 32054623, Public: priv.PublicKey(), Name: "anamorph 2026-07-19 3f9a1c"})
	if !u.ykBadge.Visible() {
		t.Error("badge hidden with a ready yubikey plugged in")
	}
	if want := "YUBIKEY 32054623"; u.ykSerial.Text != want {
		t.Errorf("ykSerial = %q, want %q", u.ykSerial.Text, want)
	}
	u.ykBadgeUpdate(yubikey.Info{Status: yubikey.NoKey, Serial: 32054623})
	if u.ykBadge.Visible() {
		t.Error("badge visible for a yubikey without an anamorph key")
	}
	u.ykBadgeUpdate(yubikey.Info{Status: yubikey.NoCard})
	if u.ykBadge.Visible() {
		t.Error("badge visible with no yubikey at all")
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
	priv, exchange := testkeys.SoftKey(t)
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
