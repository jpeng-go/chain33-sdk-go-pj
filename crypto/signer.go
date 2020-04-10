package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	secp256k1 "github.com/btcsuite/btcd/btcec"
)

var (
	SECP256k1 = "secp256k1"
	SM2       = "sm2" //TODO
	ED25519   = "ed25519" //TODO
)

type CryptoDriver interface {
	GeneratePrivateKey() []byte
	PubKeyFromPrivate(privKey []byte) []byte
	Sign(msg []byte, privKey []byte) []byte
}

func NewSignDriver(signType string) CryptoDriver {
	if signType == "secp256k1"{
		return &Secp256k1Driver{}
	} else {
		// TODO
		return nil
	}
}

type Secp256k1Driver struct { }
func (driver *Secp256k1Driver) GeneratePrivateKey() []byte {
	privKeyBytes := make([]byte, 32)
	copy(privKeyBytes[:], GetRandBytes(32))
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKeyBytes[:])
	copy(privKeyBytes[:], priv.Serialize())
	return privKeyBytes
}

func (driver *Secp256k1Driver) PubKeyFromPrivate(privKey []byte) []byte {
	_, pub := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	pubSecp256k1 := make([]byte, 33)
	copy(pubSecp256k1[:], pub.SerializeCompressed())
	return pubSecp256k1
}

func (driver *Secp256k1Driver) Sign(msg []byte, privKey []byte) []byte {
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	sig, err := priv.Sign(Sha256(msg))
	if err != nil {
		panic("Error signing secp256k1" + err.Error())
	}
	return sig.Serialize()
}

func PrivateECDSAFromByte(privKey []byte) *secp256k1.PrivateKey {
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	return priv
}

func PublicECDSAFromByte(pubKey []byte) *secp256k1.PublicKey {
	pub, _ := secp256k1.ParsePubKey(pubKey, secp256k1.S256())
	return pub
}

func GetRandBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic("Panic on a Crisis" + err.Error())
	}
	return b
}

func Sha256(b []byte) []byte {
	hasher := sha256.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}
