package yubikey

import (
	"crypto/ecdh"
	"crypto/rand"
	"regexp"
	"testing"
	"time"
)

func TestKeyName(t *testing.T) {
	pair, err := NewPair()
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}
	when := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

	solo, err := keyName("", &pair.Key.PublicKey, when)
	if err != nil {
		t.Fatalf("keyName: %v", err)
	}
	if !regexp.MustCompile(`^anamorph 2026-07-19 [0-9a-f]{6}$`).MatchString(solo) {
		t.Errorf("solo name = %q, want anamorph <date> <fingerprint>", solo)
	}

	paired, err := keyName(pairKind, &pair.Key.PublicKey, when)
	if err != nil {
		t.Fatalf("keyName: %v", err)
	}
	if !regexp.MustCompile(`^anamorph pair 2026-07-19 [0-9a-f]{6}$`).MatchString(paired) {
		t.Errorf("pair name = %q, want anamorph pair <date> <fingerprint>", paired)
	}
}

func TestIsMarker(t *testing.T) {
	tests := []struct {
		cn   string
		want bool
	}{
		{"anamorph", true}, // legacy bare marker
		{"anamorph 2026-07-19 3f9a1c", true},
		{"anamorph pair 2026-07-19 3f9a1c", true},
		{"anamorphosis", false},
		{"age-plugin-yubikey", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isMarker(tt.cn); got != tt.want {
			t.Errorf("isMarker(%q) = %v, want %v", tt.cn, got, tt.want)
		}
	}
}

func TestNewPairNamesAreUnique(t *testing.T) {
	// twins share a name, but distinct pairs must never collide - the ui
	// uses the name to recognize an already-paired card.
	a, err := NewPair()
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}
	b, err := NewPair()
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}
	if a.Name == b.Name {
		t.Errorf("two pairs got the same name %q; the fingerprint must differ", a.Name)
	}
}

func TestInfoEqualComparesName(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	a := Info{Status: Ready, Serial: 7, Public: priv.PublicKey(), Name: "anamorph 2026-07-19 aaaaaa"}
	b := a
	if !a.equal(b) {
		t.Error("identical infos compare unequal")
	}
	b.Name = "anamorph pair 2026-07-19 bbbbbb"
	if a.equal(b) {
		t.Error("infos with different names compare equal; a replaced key would go unnoticed")
	}
}
