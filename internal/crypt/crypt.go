// package crypt seals plaintext messages into a self-describing encrypted
// payload and opens them again. messages are encrypted with AES-256-GCM
// under a key derived from the password with PBKDF2-SHA256; the GCM auth
// tag doubles as integrity and wrong-password detection.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// payload wire format:
//
//	magic "SGV2" (4) | version (1) | salt (16) | nonce (12) | ctLen uint32 BE (4) | ciphertext (ctLen)
const (
	magic     = "SGV2"
	version   = 0x01
	saltLen   = 16
	nonceLen  = 12
	keyLen    = 32
	tagLen    = 16
	headerLen = len(magic) + 1 + saltLen + nonceLen + 4
)

// overhead is the number of payload bytes added on top of the plaintext.
const Overhead = headerLen + tagLen

// iterations is the PBKDF2 work factor. it is a variable only so tests can
// lower it and stay fast while still exercising the real code path; the
// application never changes it.
var Iterations = 600_000

var (
	ErrNotASecretPayload       = errors.New("crypt: no hidden message found")
	ErrUnsupportedVersion      = errors.New("crypt: message was created by a newer version of this app")
	ErrCorruptPayload          = errors.New("crypt: hidden message is corrupted")
	ErrWrongPasswordOrTampered = errors.New("crypt: wrong password, or the message was tampered with")
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
	payload = append(payload, version)
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
	if body[0] != version {
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
