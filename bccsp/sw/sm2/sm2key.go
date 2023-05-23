package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

type Sm2PrivateKey struct {
	PrivKey *PrivateKey
}

func (k *Sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

func (k *Sm2PrivateKey) SKI() []byte {
	if k.PrivKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.PrivKey.Curve, k.PrivKey.PublicKey.X, k.PrivKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *Sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *Sm2PrivateKey) Private() bool {
	return true
}

func (k *Sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &Sm2PublicKey{&k.PrivKey.PublicKey}, nil
}

type Sm2PublicKey struct {
	PubKey *PublicKey
}

func (k *Sm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalSm2PublicKey((*sm2.PublicKey)(k.PubKey))
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *Sm2PublicKey) SKI() []byte {
	if k.PubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *Sm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *Sm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *Sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

type Sm2KeyGenerator struct {
}

func (kg *Sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm2 key for  [%s]", err)
	}

	return &Sm2PrivateKey{privKey}, nil
}

type SM2KeyGenOpts struct {
	Temporary bool
}

func (opts *SM2KeyGenOpts) Algorithm() string {
	return "SM2"
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}
