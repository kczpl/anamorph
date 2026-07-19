package crypt

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// keep the suite fast while exercising the real derivation code path.
	Iterations = 4096
	os.Exit(m.Run())
}

func TestSealOpenRoundTrip(t *testing.T) {
	tests := []struct {
		name, password, message string
	}{
		{"simple", "hunter2", "meet me at dawn"},
		{"unicode", "zażółć-gęślą", "wiadomość — ünïcödé ✓ 秘密"},
		{"empty message", "pw", ""},
		{"long message", "pw", strings.Repeat("all work and no play ", 5000)},
		{"unicode password", "пароль🔑", "payload"},
		{"no password", "", "hidden but not secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Seal(tt.password, tt.message)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if len(payload) != len(tt.message)+Overhead {
				t.Errorf("payload length = %d, want %d", len(payload), len(tt.message)+Overhead)
			}
			got, err := Open(tt.password, payload)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if got != tt.message {
				t.Errorf("round trip mismatch: got %q, want %q", got, tt.message)
			}
		})
	}
}

func TestSealIsRandomized(t *testing.T) {
	a, _ := Seal("pw", "msg")
	b, _ := Seal("pw", "msg")
	if string(a) == string(b) {
		t.Error("two Seal calls produced identical payloads; salt/nonce must be fresh")
	}
}

func TestWrongPassword(t *testing.T) {
	payload, err := Seal("correct", "msg")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open("incorrect", payload); !errors.Is(err, ErrWrongPasswordOrTampered) {
		t.Errorf("got %v, want ErrWrongPasswordOrTampered", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	payload, err := Seal("pw", "msg")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	payload[len(payload)-1] ^= 0x01
	if _, err := Open("pw", payload); !errors.Is(err, ErrWrongPasswordOrTampered) {
		t.Errorf("got %v, want ErrWrongPasswordOrTampered", err)
	}
}

func TestCorruptHeader(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func([]byte) []byte
		want    error
	}{
		{"bad magic", func(p []byte) []byte { p[0] = 'X'; return p }, ErrNotASecretPayload},
		{"unknown version", func(p []byte) []byte { p[4] = 0x02; return p }, ErrUnsupportedVersion},
		{"flipped salt byte", func(p []byte) []byte { p[5] ^= 0xFF; return p }, ErrWrongPasswordOrTampered},
		{"flipped nonce byte", func(p []byte) []byte { p[21] ^= 0xFF; return p }, ErrWrongPasswordOrTampered},
		{"length mismatch", func(p []byte) []byte { p[36]++; return p }, ErrCorruptPayload},
		{"truncated body", func(p []byte) []byte { return p[:len(p)-1] }, ErrCorruptPayload},
		{"truncated below header", func(p []byte) []byte { return p[:10] }, ErrNotASecretPayload},
		{"empty payload", func(p []byte) []byte { return nil }, ErrNotASecretPayload},
		{"random garbage", func(p []byte) []byte { return []byte("definitely not a payload") }, ErrNotASecretPayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := Seal("pw", "msg")
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if _, err := Open("pw", tt.corrupt(payload)); !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEmptyPasswordIsNotAMasterKey(t *testing.T) {
	// a message sealed with a password must not open with an empty one.
	payload, err := Seal("pw", "msg")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open("", payload); !errors.Is(err, ErrWrongPasswordOrTampered) {
		t.Errorf("got %v, want ErrWrongPasswordOrTampered", err)
	}
}
