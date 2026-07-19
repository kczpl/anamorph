package yubikey

import (
	"os"
	"testing"

	"anamorph/internal/crypt"
)

// testProbe is read-only and safe to run anywhere: it reports what, if
// anything, is plugged in.
func TestProbe(t *testing.T) {
	info := Probe()
	t.Logf("probe: status=%d serial=%d hasKey=%v", info.Status, info.Serial, info.Public != nil)
}

// testHardwareRoundTrip exercises a real yubikey end to end: setup (which
// GENERATES A KEY in a free retired piv slot on the plugged-in card, if
// none exists yet), then a full seal/open round trip through the hardware.
// it only runs when explicitly requested, since it writes to the card.
func TestHardwareRoundTrip(t *testing.T) {
	if os.Getenv("ANAMORPH_HW_TEST") == "" {
		t.Skip("set ANAMORPH_HW_TEST=1 to run against a real yubikey (writes to the card)")
	}
	if Probe().Status == NoCard {
		t.Skip("no yubikey plugged in")
	}

	info, err := Setup()
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if info.Status != Ready || info.Public == nil {
		t.Fatalf("Setup left status=%d, want Ready with a public key", info.Status)
	}
	t.Logf("yubikey %d ready", info.Serial)

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
// Import REPLACES ANY EXISTING ANAMORPH KEY on the plugged-in yubikey with
// a fresh software-generated pair key, then the same payload is opened both
// through the hardware and through the software twin - proving the two are
// interchangeable. it only runs when explicitly requested.
func TestHardwareImportRoundTrip(t *testing.T) {
	if os.Getenv("ANAMORPH_HW_TEST") == "" {
		t.Skip("set ANAMORPH_HW_TEST=1 to run against a real yubikey (writes to the card)")
	}
	if Probe().Status == NoCard {
		t.Skip("no yubikey plugged in")
	}

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
