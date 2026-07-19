package crypt

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// softKey stands in for a yubikey: a software P-256 key whose ECDH half
// exercises the exact same code path the hardware provides.
func softKey(t *testing.T) (*ecdh.PrivateKey, Exchange) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, func(ephemeral *ecdh.PublicKey) ([]byte, error) {
		return priv.ECDH(ephemeral)
	}
}

func TestSealToOpenWithRoundTrip(t *testing.T) {
	tests := []struct {
		name, message string
	}{
		{"simple", "meet me at dawn"},
		{"unicode", "wiadomość - ünïcödé ✓ 秘密"},
		{"empty message", ""},
		{"long message", strings.Repeat("all work and no play ", 5000)},
	}
	priv, exchange := softKey(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := SealTo(priv.PublicKey(), tt.message)
			if err != nil {
				t.Fatalf("SealTo: %v", err)
			}
			if len(payload) != len(tt.message)+Overhead {
				t.Errorf("payload length = %d, want %d", len(payload), len(tt.message)+Overhead)
			}
			got, err := OpenWith(exchange, payload)
			if err != nil {
				t.Fatalf("OpenWith: %v", err)
			}
			if got != tt.message {
				t.Errorf("round trip mismatch: got %q, want %q", got, tt.message)
			}
		})
	}
}

func TestOpenWithWrongKey(t *testing.T) {
	priv, _ := softKey(t)
	_, wrongExchange := softKey(t)
	payload, err := SealTo(priv.PublicKey(), "msg")
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if _, err := OpenWith(wrongExchange, payload); !errors.Is(err, ErrWrongYubiKeyOrTampered) {
		t.Errorf("got %v, want ErrWrongYubiKeyOrTampered", err)
	}
}

func TestOpenWithCorruptPayload(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func([]byte) []byte
		want    error
	}{
		{"bad magic", func(p []byte) []byte { p[0] = 'X'; return p }, ErrNotASecretPayload},
		{"password version", func(p []byte) []byte { p[4] = versionPassword; return p }, ErrNeedsPassword},
		{"unknown version", func(p []byte) []byte { p[4] = 0x03; return p }, ErrUnsupportedVersion},
		{"mangled ephemeral point", func(p []byte) []byte { p[6] ^= 0xFF; return p }, ErrCorruptPayload},
		{"flipped nonce byte", func(p []byte) []byte { p[71] ^= 0xFF; return p }, ErrWrongYubiKeyOrTampered},
		{"tampered ciphertext", func(p []byte) []byte { p[len(p)-1] ^= 0x01; return p }, ErrWrongYubiKeyOrTampered},
		{"length mismatch", func(p []byte) []byte { p[85]++; return p }, ErrCorruptPayload},
		{"truncated body", func(p []byte) []byte { return p[:len(p)-1] }, ErrCorruptPayload},
		{"truncated below header", func(p []byte) []byte { return p[:40] }, ErrCorruptPayload},
		{"empty payload", func(p []byte) []byte { return nil }, ErrNotASecretPayload},
	}
	priv, exchange := softKey(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := SealTo(priv.PublicKey(), "msg")
			if err != nil {
				t.Fatalf("SealTo: %v", err)
			}
			if _, err := OpenWith(exchange, tt.corrupt(payload)); !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOpenRejectsYubiKeyPayload(t *testing.T) {
	// the password path must route a yubikey payload to the right error,
	// not report a wrong password.
	priv, _ := softKey(t)
	payload, err := SealTo(priv.PublicKey(), "msg")
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if _, err := Open("pw", payload); !errors.Is(err, ErrNeedsYubiKey) {
		t.Errorf("got %v, want ErrNeedsYubiKey", err)
	}
}

func TestNeedsYubiKey(t *testing.T) {
	priv, _ := softKey(t)
	ykPayload, err := SealTo(priv.PublicKey(), "msg")
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	pwPayload, err := Seal("pw", "msg")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if needs, err := NeedsYubiKey(ykPayload); err != nil || !needs {
		t.Errorf("yubikey payload: needs=%v err=%v, want true, nil", needs, err)
	}
	if needs, err := NeedsYubiKey(pwPayload); err != nil || needs {
		t.Errorf("password payload: needs=%v err=%v, want false, nil", needs, err)
	}
	if _, err := NeedsYubiKey([]byte("garbage")); !errors.Is(err, ErrNotASecretPayload) {
		t.Errorf("garbage: got %v, want ErrNotASecretPayload", err)
	}
	pwPayload[4] = 0x03
	if _, err := NeedsYubiKey(pwPayload); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("future version: got %v, want ErrUnsupportedVersion", err)
	}
}

func TestSealToIsRandomized(t *testing.T) {
	priv, _ := softKey(t)
	a, _ := SealTo(priv.PublicKey(), "msg")
	b, _ := SealTo(priv.PublicKey(), "msg")
	if string(a) == string(b) {
		t.Error("two SealTo calls produced identical payloads; the ephemeral key must be fresh")
	}
}
