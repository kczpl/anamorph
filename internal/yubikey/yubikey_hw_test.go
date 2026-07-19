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
