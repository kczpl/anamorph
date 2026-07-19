// package crypt seals plaintext messages into a self-describing encrypted
// payload and opens them again. messages are encrypted with AES-256-GCM
// under one of two kinds of key: derived from a password with
// PBKDF2-SHA256, or agreed via ECDH against a yubikey that holds the
// private half in hardware. the GCM auth tag doubles as integrity and
// wrong-key detection.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// payload wire formats:
//
//	password: magic "SGV2" (4) | version 0x01 (1) | salt (16)          | nonce (12) | ctLen uint32 BE (4) | ciphertext (ctLen)
//	yubikey:  magic "SGV2" (4) | version 0x02 (1) | ephemeral pub (65) | nonce (12) | ctLen uint32 BE (4) | ciphertext (ctLen)
const (
	magic           = "SGV2"
	versionPassword = 0x01
	versionYubiKey  = 0x02
	saltLen         = 16
	ephLen          = 65 // uncompressed P-256 point
	nonceLen        = 12
	keyLen          = 32
	tagLen          = 16
	headerLen       = len(magic) + 1 + saltLen + nonceLen + 4
	ykHeaderLen     = len(magic) + 1 + ephLen + nonceLen + 4
)

// hkdfInfo domain-separates the key derived for yubikey payloads.
const hkdfInfo = "anamorph yubikey seal v1"

// overhead is the number of payload bytes added on top of the plaintext,
// whichever sealing method is used; the yubikey envelope is the larger one.
const Overhead = ykHeaderLen + tagLen

// iterations is the PBKDF2 work factor. it is a variable only so tests can
// lower it and stay fast while still exercising the real code path; the
// application never changes it.
var Iterations = 600_000

var (
	ErrNotASecretPayload       = errors.New("crypt: no hidden message found")
	ErrUnsupportedVersion      = errors.New("crypt: message was created by a newer version of this app")
	ErrCorruptPayload          = errors.New("crypt: hidden message is corrupted")
	ErrWrongPasswordOrTampered = errors.New("crypt: wrong password, or the message was tampered with")
	ErrWrongYubiKeyOrTampered  = errors.New("crypt: wrong yubikey, or the message was tampered with")
	ErrNeedsYubiKey            = errors.New("crypt: this message unlocks with a yubikey")
	ErrNeedsPassword           = errors.New("crypt: this message unlocks with a password")
)

// seal encrypts plaintext with a key derived from password and returns the
// full payload. a fresh salt and nonce are drawn on every call. an empty
// password is allowed: the message is then only obfuscated, not secret,
// but the GCM tag still guards its integrity.
func Seal(password, plaintext string) ([]byte, error) {
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	gcm, err := newGCM(password, salt)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	payload := make([]byte, 0, headerLen+len(ciphertext))
	payload = append(payload, magic...)
	payload = append(payload, versionPassword)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(ciphertext)))
	return append(payload, ciphertext...), nil
}

// open decrypts a payload produced by Seal. cheap structural checks run
// first; the expensive key derivation only happens for well-formed payloads.
func Open(password string, payload []byte) (string, error) {
	if len(payload) < headerLen || string(payload[:len(magic)]) != magic {
		return "", ErrNotASecretPayload
	}
	body := payload[len(magic):]
	switch body[0] {
	case versionPassword:
	case versionYubiKey:
		return "", ErrNeedsYubiKey
	default:
		return "", ErrUnsupportedVersion
	}
	salt := body[1 : 1+saltLen]
	nonce := body[1+saltLen : 1+saltLen+nonceLen]
	ctLen := binary.BigEndian.Uint32(body[1+saltLen+nonceLen:])
	ciphertext := body[1+saltLen+nonceLen+4:]
	if int(ctLen) != len(ciphertext) || ctLen < tagLen {
		return "", ErrCorruptPayload
	}

	gcm, err := newGCM(password, salt)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrWrongPasswordOrTampered
	}
	return string(plaintext), nil
}

// exchange performs the recipient's half of an ECDH agreement: given the
// ephemeral public key from a payload it returns the shared secret. the
// yubikey package provides one backed by hardware; tests use software keys.
type Exchange func(ephemeral *ecdh.PublicKey) ([]byte, error)

// sealTo encrypts plaintext so that only the holder of the private half of
// recipient can read it. a fresh ephemeral P-256 key agrees on a shared
// secret with recipient; HKDF-SHA256 stretches the secret into the AES key
// and the ephemeral public key travels in the payload. sealing needs no
// hardware - only opening does.
func SealTo(recipient *ecdh.PublicKey, plaintext string) ([]byte, error) {
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	ephPub := ephemeral.PublicKey().Bytes()
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := sharedGCM(shared, ephPub)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	payload := make([]byte, 0, ykHeaderLen+len(ciphertext))
	payload = append(payload, magic...)
	payload = append(payload, versionYubiKey)
	payload = append(payload, ephPub...)
	payload = append(payload, nonce...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(ciphertext)))
	return append(payload, ciphertext...), nil
}

// openWith decrypts a payload produced by SealTo. exchange supplies the
// shared secret for the payload's ephemeral key - the single step that
// happens inside the yubikey.
func OpenWith(exchange Exchange, payload []byte) (string, error) {
	if len(payload) < len(magic)+1 || string(payload[:len(magic)]) != magic {
		return "", ErrNotASecretPayload
	}
	switch payload[len(magic)] {
	case versionYubiKey:
	case versionPassword:
		return "", ErrNeedsPassword
	default:
		return "", ErrUnsupportedVersion
	}
	if len(payload) < ykHeaderLen {
		return "", ErrCorruptPayload
	}
	body := payload[len(magic)+1:]
	ephPub := body[:ephLen]
	nonce := body[ephLen : ephLen+nonceLen]
	ctLen := binary.BigEndian.Uint32(body[ephLen+nonceLen:])
	ciphertext := body[ephLen+nonceLen+4:]
	if int(ctLen) != len(ciphertext) || ctLen < tagLen {
		return "", ErrCorruptPayload
	}

	ephemeral, err := ecdh.P256().NewPublicKey(ephPub)
	if err != nil {
		return "", ErrCorruptPayload
	}
	shared, err := exchange(ephemeral)
	if err != nil {
		return "", err
	}
	gcm, err := sharedGCM(shared, ephPub)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrWrongYubiKeyOrTampered
	}
	return string(plaintext), nil
}

// needsYubiKey reports which unlock method a payload wants, so the ui can
// route to the password field or the yubikey without asking the user.
func NeedsYubiKey(payload []byte) (bool, error) {
	if len(payload) < len(magic)+1 || string(payload[:len(magic)]) != magic {
		return false, ErrNotASecretPayload
	}
	switch payload[len(magic)] {
	case versionPassword:
		return false, nil
	case versionYubiKey:
		return true, nil
	default:
		return false, ErrUnsupportedVersion
	}
}

func newGCM(password string, salt []byte) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sharedGCM builds the AEAD for a yubikey payload from the ECDH shared
// secret, bound to the ephemeral public key that produced it.
func sharedGCM(shared, ephPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, ephPub, hkdfInfo, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
