package yubikey

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"anamorph/internal/crypt"
)

// testProbe is read-only and safe to run anywhere: it reports what, if
// anything, is plugged in.
func TestProbe(t *testing.T) {
	info := Probe()
	t.Logf("probe: status=%d serial=%d hasKey=%v", info.Status, info.Serial, info.Public != nil)
}

// the hardware tests never touch a real anamorph key: useTestMarker points
// the whole package at a separate "anamorph-test" certificate family for
// the duration of a test, so Setup, Import and Exchange all work against a
// key of their own in a slot of their own. neither family's name prefixes
// the other's, so the app is blind to the test key and vice versa.
func useTestMarker(t *testing.T) {
	t.Helper()
	real := markerCN
	markerCN = "anamorph-test"
	t.Cleanup(func() { markerCN = real })
}

// testHardwareRoundTrip exercises a real yubikey end to end: setup (which
// generates an anamorph-test key in a free retired piv slot, unless one
// survived an earlier run), then a full seal/open round trip through the
// hardware. it only runs when explicitly requested, since it may write to
// the card; on success the test key is removed again (see removeTestKey).
func TestHardwareRoundTrip(t *testing.T) {
	if os.Getenv("ANAMORPH_HW_TEST") == "" {
		t.Skip("set ANAMORPH_HW_TEST=1 to run against a real yubikey (writes to the card)")
	}
	useTestMarker(t)
	if Probe().Status == NoCard {
		t.Skip("no yubikey plugged in")
	}
	removeTestKey(t)

	info, err := Setup()
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if info.Status != Ready || info.Public == nil {
		t.Fatalf("Setup left status=%d, want Ready with a public key", info.Status)
	}
	t.Logf("yubikey %d ready with %q", info.Serial, info.Name)

	const message = "hardware says hello"
	payload, err := crypt.SealTo(info.Public, message)
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	got, err := crypt.OpenWith(Exchange, payload)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	if got != message {
		t.Errorf("round trip mismatch: got %q, want %q", got, message)
	}
}

// testHardwareImportRoundTrip exercises the pairing path on a real card:
// Import writes a fresh software-generated pair key to the plugged-in
// yubikey, then the same payload is opened both through the hardware and
// through the software twin - proving the two are interchangeable. it runs
// entirely in the anamorph-test family, so the key it replaces (if an
// earlier run left one) and the key it writes are both test keys; a real
// anamorph key on the card is never touched. it only runs when explicitly
// requested, and on success the test key is removed (see removeTestKey).
func TestHardwareImportRoundTrip(t *testing.T) {
	if os.Getenv("ANAMORPH_HW_TEST") == "" {
		t.Skip("set ANAMORPH_HW_TEST=1 to run against a real yubikey (writes to the card)")
	}
	useTestMarker(t)
	if Probe().Status == NoCard {
		t.Skip("no yubikey plugged in")
	}
	removeTestKey(t)

	pair, err := NewPair()
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}
	info, err := Import(pair)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if info.Status != Ready || info.Public == nil {
		t.Fatalf("Import left status=%d, want Ready with a public key", info.Status)
	}
	if info.Name != pair.Name {
		t.Errorf("card reports name %q, want %q", info.Name, pair.Name)
	}
	t.Logf("yubikey %d carries %q", info.Serial, info.Name)

	const message = "twins say hello"
	payload, err := crypt.SealTo(info.Public, message)
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	got, err := crypt.OpenWith(Exchange, payload)
	if err != nil {
		t.Fatalf("OpenWith via hardware: %v", err)
	}
	if got != message {
		t.Errorf("hardware twin: got %q, want %q", got, message)
	}

	soft, err := pair.Key.ECDH()
	if err != nil {
		t.Fatalf("ECDH convert: %v", err)
	}
	got, err = crypt.OpenWith(soft.ECDH, payload)
	if err != nil {
		t.Fatalf("OpenWith via software twin: %v", err)
	}
	if got != message {
		t.Errorf("software twin: got %q, want %q", got, message)
	}
}

// removeTestKey registers a cleanup that deletes the anamorph-test key, so
// a successful run leaves nothing behind. deleting a piv key is a yubico
// extension that piv-go does not speak, so the cleanup shells out to
// ykman, and the card itself only supports it from firmware 5.7 on. when
// either is missing the test key stays parked in its one slot and the
// cleanup says so - later runs find and reuse it, so the tests never claim
// a second slot. after a FAILED test the key is kept on purpose, for
// inspection. must be called after useTestMarker, so the cleanups run in
// the right order: first the removal, then the marker restore.
func removeTestKey(t *testing.T) {
	t.Cleanup(func() {
		var (
			serial  uint32
			version piv.Version
			slot    piv.Slot
			found   bool
		)
		err := withCard(func(yk *piv.YubiKey) error {
			serial, _ = yk.Serial()
			version = yk.Version()
			slot, _, found = findKey(yk)
			return nil
		})
		if err != nil || !found {
			return // nothing on the card to clean up
		}
		slotArg := fmt.Sprintf("%x", slot.Key)
		if t.Failed() {
			t.Logf("cleanup: leaving the test key in slot %s for inspection; remove it with `ykman piv keys delete %s` and `ykman piv certificates delete %s`", slotArg, slotArg, slotArg)
			return
		}
		if version.Major < 5 || (version.Major == 5 && version.Minor < 7) {
			t.Logf("cleanup: firmware %d.%d.%d cannot delete piv keys (5.7+ only); the test key stays parked in slot %s for the next run", version.Major, version.Minor, version.Patch, slotArg)
			return
		}
		if _, err := exec.LookPath("ykman"); err != nil {
			t.Logf("cleanup: ykman not installed (brew install ykman); the test key stays parked in slot %s for the next run", slotArg)
			return
		}
		var device []string
		if serial != 0 {
			device = []string{"--device", fmt.Sprint(serial)}
		}
		mk := hex.EncodeToString(piv.DefaultManagementKey)
		// the key goes first: if deleting it fails, the marker certificate
		// stays too and the slot remains identifiable, instead of holding
		// an invisible orphan key.
		for _, sub := range [][]string{
			{"piv", "keys", "delete"},
			{"piv", "certificates", "delete"},
		} {
			args := append(append(append([]string{}, device...), sub...), "-m", mk, slotArg)
			if out, err := exec.Command("ykman", args...).CombinedOutput(); err != nil {
				t.Logf("cleanup: ykman %s %s: %v\n%s", strings.Join(sub, " "), slotArg, err, out)
				return
			}
		}
		t.Logf("cleanup: removed the test key from slot %s", slotArg)
	})
}
