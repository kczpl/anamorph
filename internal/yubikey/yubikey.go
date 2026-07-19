// package yubikey finds (or creates) the anamorph key on a plugged-in
// yubikey and performs the hardware half of decryption. the private key is
// generated inside the yubikey's piv applet and can never leave it; the
// only operation the card exposes to the app is the ECDH agreement that
// Exchange runs.
package yubikey

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// anamorph keeps its key in one of the piv "retired" slots (0x82-0x95),
// leaving the four primary slots to real certificates. the slot is found
// again on later plugs by the marker certificate stored next to the key; a
// slot holding someone else's key is never touched.
const (
	slotFirst = 0x82
	slotLast  = 0x95
	markerCN  = "anamorph"
	pairKind  = "pair"
)

type Status int

const (
	NoCard Status = iota // no yubikey plugged in (or the card is unreachable)
	NoKey                // yubikey present, not set up for anamorph yet
	Ready                // anamorph key found and usable
)

// info is the result of probing for a yubikey.
type Info struct {
	Status Status
	Serial uint32
	Public *ecdh.PublicKey // the recipient key to seal to; set when Ready
	Name   string          // the key's display name from its marker certificate
}

var (
	ErrNoCard     = errors.New("yubikey: no yubikey detected")
	ErrNoKey      = errors.New("yubikey: this yubikey is not set up for anamorph")
	ErrNoFreeSlot = errors.New("yubikey: no free piv slot on this yubikey")
	ErrLocked     = errors.New("yubikey: piv uses a custom management key")
)

// probe reports whether a yubikey is plugged in and whether it already
// carries an anamorph key. failures to talk to the card count as absence:
// callers only need to know what they can use right now.
func Probe() Info {
	var info Info
	if err := withCard(func(yk *piv.YubiKey) error {
		info = probeCard(yk)
		return nil
	}); err != nil {
		return Info{Status: NoCard}
	}
	return info
}

// setup generates the anamorph key if the plugged yubikey does not have
// one yet, and returns the resulting state; it is idempotent. the key is
// created with no pin and no touch requirement: plugging the yubikey in is
// the whole credential. setup never overwrites a slot that holds a key.
func Setup() (Info, error) {
	var info Info
	err := withCard(func(yk *piv.YubiKey) error {
		info = probeCard(yk)
		if info.Status == Ready {
			return nil
		}
		slot, ok := freeSlot(yk)
		if !ok {
			return ErrNoFreeSlot
		}
		pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: piv.TouchPolicyNever,
		})
		if err != nil {
			var authErr piv.AuthErr
			if errors.As(err, &authErr) {
				return ErrLocked
			}
			return err
		}
		name, err := keyName("", pub, time.Now())
		if err != nil {
			return err
		}
		cert, err := markerCert(yk, slot, pub, name)
		if err != nil {
			return err
		}
		if err := yk.SetCertificate(piv.DefaultManagementKey, slot, cert); err != nil {
			return err
		}
		info = probeCard(yk)
		return nil
	})
	return info, err
}

// pair is the shared identity written to two (or more) yubikeys during
// pairing: a software-generated key and its display name. every card that
// receives it becomes an interchangeable twin - any of them opens images
// sealed to the pair. the key exists in host memory only for the duration
// of the ceremony; go offers no guaranteed wiping, so the caller should
// simply let it fall out of scope as soon as the last card is written.
type Pair struct {
	Key  *ecdsa.PrivateKey
	Name string
}

// newPair generates the software key a pairing ceremony will import into
// each yubikey. unlike Setup, the private half is briefly outside hardware -
// that is the price of having the same key on two cards.
func NewPair() (*Pair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	name, err := keyName(pairKind, &key.PublicKey, time.Now())
	if err != nil {
		return nil, err
	}
	return &Pair{Key: key, Name: name}, nil
}

// import writes the pair's key into the plugged-in yubikey, making it one
// of the twins. an existing anamorph key on the card is replaced in place -
// callers must get the user's explicit go-ahead first, since that orphans
// every image sealed to the old key - but slots owned by other software are
// never touched.
func Import(p *Pair) (Info, error) {
	var info Info
	err := withCard(func(yk *piv.YubiKey) error {
		slot, _, ok := findKey(yk)
		if !ok {
			if slot, ok = freeSlot(yk); !ok {
				return ErrNoFreeSlot
			}
		}
		if err := yk.SetPrivateKeyInsecure(piv.DefaultManagementKey, slot, p.Key, piv.Key{
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: piv.TouchPolicyNever,
		}); err != nil {
			var authErr piv.AuthErr
			if errors.As(err, &authErr) {
				return ErrLocked
			}
			return err
		}
		cert, err := softMarkerCert(p)
		if err != nil {
			return err
		}
		if err := yk.SetCertificate(piv.DefaultManagementKey, slot, cert); err != nil {
			return err
		}
		info = probeCard(yk)
		return nil
	})
	return info, err
}

// exchange performs the yubikey's half of the ECDH agreement for a sealed
// payload: the one operation that needs the hardware.
func Exchange(ephemeral *ecdh.PublicKey) ([]byte, error) {
	var shared []byte
	err := withCard(func(yk *piv.YubiKey) error {
		slot, cert, ok := findKey(yk)
		if !ok {
			return ErrNoKey
		}
		priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PINPolicy: piv.PINPolicyNever})
		if err != nil {
			return err
		}
		key, ok := priv.(*piv.ECDSAPrivateKey)
		if !ok {
			return ErrNoKey
		}
		shared, err = key.ECDH(ephemeral)
		return err
	})
	return shared, err
}

// withCard opens the first plugged-in yubikey exclusively, runs fn against
// it and releases the card again. ErrNoCard covers everything from "not
// plugged in" to "another program holds it".
func withCard(fn func(*piv.YubiKey) error) error {
	cards, err := piv.Cards()
	if err != nil {
		return ErrNoCard
	}
	name := ""
	for _, c := range cards {
		if strings.Contains(strings.ToLower(c), "yubikey") {
			name = c
			break
		}
	}
	if name == "" {
		return ErrNoCard
	}
	yk, err := piv.Open(name)
	if err != nil {
		return ErrNoCard
	}
	defer yk.Close()
	return fn(yk)
}

func probeCard(yk *piv.YubiKey) Info {
	info := Info{Status: NoKey}
	if serial, err := yk.Serial(); err == nil {
		info.Serial = serial
	}
	if _, cert, ok := findKey(yk); ok {
		if pub, err := certECDH(cert); err == nil {
			info.Status = Ready
			info.Public = pub
			info.Name = cert.Subject.CommonName
		}
	}
	return info
}

// keyName builds the display name stored in a key's marker certificate:
// the app name, an optional kind, the creation date and a short fingerprint
// of the public key - e.g. "anamorph pair 2026-07-19 3f9a1c". piv tools
// show the certificate subject, so a key found on a yubikey months later
// explains where it came from; paired twins carry the identical name.
func keyName(kind string, pub crypto.PublicKey, now time.Time) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	parts := []string{markerCN}
	if kind != "" {
		parts = append(parts, kind)
	}
	parts = append(parts, now.Format("2006-01-02"), hex.EncodeToString(sum[:3]))
	return strings.Join(parts, " "), nil
}

// isMarker recognizes anamorph marker certificates by subject: the bare
// legacy name or any name it prefixes.
func isMarker(cn string) bool {
	return cn == markerCN || strings.HasPrefix(cn, markerCN+" ")
}

// findKey scans the retired slots for anamorph's marker certificate.
func findKey(yk *piv.YubiKey) (piv.Slot, *x509.Certificate, bool) {
	for id := uint32(slotFirst); id <= slotLast; id++ {
		slot, ok := piv.RetiredKeyManagementSlot(id)
		if !ok {
			continue
		}
		cert, err := yk.Certificate(slot)
		if err != nil || !isMarker(cert.Subject.CommonName) {
			continue
		}
		return slot, cert, true
	}
	return piv.Slot{}, nil, false
}

// freeSlot returns the first retired slot that provably holds no key. a
// slot with a certificate is taken; a bare key without one is caught by
// KeyInfo on 5.3+ firmware and by the attestation check on older keys. (a
// key imported - not generated - into a retired slot on pre-5.3 firmware
// would be missed; no mainstream tool creates that combination.)
func freeSlot(yk *piv.YubiKey) (piv.Slot, bool) {
	for id := uint32(slotFirst); id <= slotLast; id++ {
		slot, ok := piv.RetiredKeyManagementSlot(id)
		if !ok {
			continue
		}
		if _, err := yk.Certificate(slot); err == nil {
			continue
		}
		if _, err := yk.KeyInfo(slot); err == nil {
			continue
		}
		if _, err := yk.Attest(slot); err == nil {
			continue
		}
		return slot, true
	}
	return piv.Slot{}, false
}

// markerTemplate is the certificate shape shared by both signing paths:
// its only jobs are to be found again on the next plug and to say, via its
// subject, what the key is and where it came from.
func markerTemplate(name string, now time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now,
		NotAfter:     now.AddDate(100, 0, 0),
	}
}

// markerCert builds the marker certificate for a key generated on the
// card, signed by the hardware key itself - the private half is not
// available anywhere else.
func markerCert(yk *piv.YubiKey, slot piv.Slot, pub crypto.PublicKey, name string) (*x509.Certificate, error) {
	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{PINPolicy: piv.PINPolicyNever})
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("yubikey: generated key cannot sign")
	}
	tmpl := markerTemplate(name, time.Now())
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// softMarkerCert builds the marker certificate for a pair key, signed in
// software: during the ceremony the private key is still in memory.
func softMarkerCert(p *Pair) (*x509.Certificate, error) {
	tmpl := markerTemplate(p.Name, time.Now())
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.Key.PublicKey, p.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func certECDH(cert *x509.Certificate) (*ecdh.PublicKey, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("yubikey: marker certificate holds a non-ecdsa key")
	}
	return pub.ECDH()
}
