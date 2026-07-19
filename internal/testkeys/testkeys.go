// package testkeys provides the software stand-in for a yubikey shared by
// tests across the module.
package testkeys

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// SoftKey returns a fresh software P-256 key and its ECDH half - the
// drop-in replacement for the one operation a real yubikey performs, so
// tests exercise the exact same code path the hardware provides.
func SoftKey(t *testing.T) (*ecdh.PrivateKey, func(*ecdh.PublicKey) ([]byte, error)) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, func(ephemeral *ecdh.PublicKey) ([]byte, error) {
		return priv.ECDH(ephemeral)
	}
}
