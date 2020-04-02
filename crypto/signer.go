package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	secp256k1 "github.com/btcsuite/btcd/btcec"
)

var (
	SECP256k1 = 1
	SM2       = 2 //TODO
	ED25519   = 3 //TODO
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
	pubSecp256k1 := make([]byte, 32)
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

func GetRandBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic("Panic on a Crisis" + err.Error())
	}
	return b
}

// Sha2Sum Returns hash: SHA256( SHA256( data ) )
// Where possible, using ShaHash() should be a bit faster
func Sha256(b []byte) []byte {
	tmp := sha256.Sum256(b)
	tmp = sha256.Sum256(tmp[:])
	return tmp[:]
}

func AddressFromPubKey(key []byte) (string, error) {
	return "", nil
}