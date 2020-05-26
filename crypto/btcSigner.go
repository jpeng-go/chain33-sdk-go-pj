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

func GeneratePrivateKey() []byte {
	privKeyBytes := make([]byte, 32)
	copy(privKeyBytes[:], getRandBytes(32))
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKeyBytes[:])
	copy(privKeyBytes[:], priv.Serialize())
	return privKeyBytes
}

func PubKeyFromPrivate(privKey []byte) []byte {
	_, pub := secp256k1.PrivKeyFromBytes(secp256k1.S256(), privKey[:])
	pubSecp256k1 := make([]byte, 33)
	copy(pubSecp256k1[:], pub.SerializeCompressed())
	return pubSecp256k1
}

func Sign(msg []byte, privKey []byte) []byte {
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

func getRandBytes(numBytes int) []byte {
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